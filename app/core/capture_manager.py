import os
import time
import collections
import logging
from pathlib import Path
import tempfile
import atexit
import signal
from datetime import datetime, timezone
from scapy.sendrecv import AsyncSniffer
from scapy.arch.common import compile_filter
from scapy.utils import PcapWriter
from scapy.packet import Packet
from scapy.arch import get_if_list

from app.core.config import DATA_DIR
from app.core.bridge import packet_bridge
from app.storage.database import router

logger = logging.getLogger(__name__)

# Temporary directories configuration
TEMP_PCAP_DIR = DATA_DIR / "uploads"
TEMP_PCAP_DIR.mkdir(parents=True, exist_ok=True)

class LiveCaptureManager:
    def __init__(self):
        self.sniffer = None
        self.session_id = None
        self.interface = None
        self.bpf_filter = None
        self.pcap_writer = None
        self.temp_pcap_path = None
        self.is_capturing = False
        self.is_paused = False

        # --- capture_live() upgrades ---
        # filter_private: mirrors ProductionWebRTCCaptureEngine(filter_private=False)
        # When True, private/loopback/link-local IPs are excluded from ip_store extraction.
        self.filter_private: bool = False

        # Optional hard stop after N packets (0 = unlimited), mirrors capture_live(count=0)
        self.count_limit: int = 0

        # Optional timeout in seconds (None = unlimited), mirrors capture_live(timeout=None)
        self.capture_timeout: int | None = None

        # Cached final report produced by generate_report() on stop
        self._last_report: dict | None = None
        # ---

        # Display Ring Buffer capped at 256MB
        self.display_ring_buffer = collections.deque()
        self.ring_buffer_bytes = 0
        self.max_memory_bytes = 256 * 1024 * 1024  # 256MB

        # Telemetry metrics
        self.packet_count = 0
        self.dropped_packets = 0
        self.start_time = 0
        self.bytes_captured = 0
        self.last_stats_write = 0

        # Register atexit and signal handlers
        atexit.register(self.shutdown)
        try:
            signal.signal(signal.SIGTERM, self.handle_sigterm)
        except ValueError:
            # Not in main thread, ignore
            pass

    def get_interfaces(self) -> list[dict]:
        """Get available network interfaces with friendly descriptions."""
        interfaces = []
        try:
            from scapy.all import conf
            try:
                conf.ifaces.reload()
            except Exception as reload_err:
                logger.error(f"Error reloading Scapy interfaces: {reload_err}")
            # Loop through all resolved interfaces
            for iface_name, iface in conf.ifaces.items():
                desc = iface.description or iface.name
                ip_addr = iface.ip or "No IP"
                
                # Check if it has a valid IP address or is loopback/active
                is_active = (iface.ip and iface.ip != "0.0.0.0") or "loopback" in iface.name.lower()
                
                interfaces.append({
                    "id": iface.network_name or iface_name,
                    "name": iface.name,
                    "description": f"{iface.name} ({desc})",
                    "ip": ip_addr,
                    "is_active": is_active
                })
                
            # Sort active interfaces to the top of the list!
            interfaces.sort(key=lambda x: not x["is_active"])
            
        except Exception as e:
            logger.error(f"Error listing network interfaces: {e}")
            interfaces = [{"id": "any", "name": "any", "description": "All Interfaces (Any)", "ip": "0.0.0.0", "is_active": True}]
        return interfaces

    def validate_filter(self, bpf_filter: str) -> bool:
        """Validate BPF filter syntax using Scapy's compile_filter."""
        if not bpf_filter:
            return True
        try:
            compile_filter(bpf_filter, linktype=1)
            return True
        except Exception as e:
            logger.error(f"BPF filter compilation failed: {e}")
            return False

    def start_capture(
        self,
        interface: str,
        bpf_filter: str = "",
        filter_private: bool = False,
        count_limit: int = 0,
        capture_timeout: int | None = None,
    ) -> str:
        """
        Start capturing packets in the background.

        Args:
            interface:       Network interface name, or 'simulated'.
            bpf_filter:      BPF filter expression (empty = VoIP-focused default).
            filter_private:  When True, private/loopback/link-local IPs are excluded
                             from the ip_store extraction report — mirrors
                             ProductionWebRTCCaptureEngine(filter_private=...) param.
            count_limit:     Stop automatically after this many packets (0 = unlimited),
                             mirrors capture_live(count=N).
            capture_timeout: Stop automatically after this many seconds (None = unlimited),
                             mirrors capture_live(timeout=N).
        """
        if self.is_capturing:
            raise ValueError("Capture already in progress")

        if not bpf_filter:
            bpf_filter = "udp or (tcp and (port 5060 or port 5061 or port 443 or port 53 or port 5353 or port 3478))"

        if bpf_filter and not self.validate_filter(bpf_filter):
            raise ValueError(f"Malformed BPF filter expression: {bpf_filter}")

        # Store capture_live() options
        self.filter_private = filter_private
        self.count_limit = count_limit
        self.capture_timeout = capture_timeout
        self._last_report = None

        # Apply filter_private to ip_store so extraction respects the flag
        try:
            from app.protocols.voip_manager import voip_manager
            voip_manager.ip_store.filter_private = filter_private
        except Exception:
            pass

        self.session_id = f"live_{int(time.time())}"
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.temp_pcap_path = TEMP_PCAP_DIR / f"cyberdeep_{self.session_id}.pcap"

        # Reset ring buffer and metrics
        self.display_ring_buffer.clear()
        self.ring_buffer_bytes = 0
        self.packet_count = 0
        self.dropped_packets = 0
        self.bytes_captured = 0
        self.start_time = time.time()

        # Startup banner — mirrors capture_live() print block
        logger.info("[*] Production capture engine starting...")
        logger.info(f"[*] Interface       : {interface}")
        logger.info(f"[*] BPF Filter      : {bpf_filter}")
        logger.info(f"[*] Private IP filter: {'ON' if filter_private else 'OFF'}")
        logger.info(f"[*] Packet limit    : {count_limit if count_limit else 'unlimited'}")
        logger.info(f"[*] Timeout         : {capture_timeout if capture_timeout else 'unlimited'}s")

        # Open PCAP writer
        try:
            self.pcap_writer = PcapWriter(str(self.temp_pcap_path), append=True, sync=True)
        except Exception as e:
            logger.error(f"Failed to create PCAP writer at {self.temp_pcap_path}: {e}")
            raise RuntimeError(f"Failed to initialize PCAP output: {e}")

        # Start capture mechanism
        self.is_capturing = True
        self.is_paused = False

        if interface == "simulated":
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                self.simulation_task = loop.create_task(self.run_simulation())
            except RuntimeError:
                import threading
                def thread_target():
                    asyncio.run(self.run_simulation())
                self.simulation_thread = threading.Thread(target=thread_target, daemon=True)
                self.simulation_thread.start()
            logger.info(f"Simulated capture session {self.session_id} started.")
            return self.session_id

        # Start Scapy sniffer with count and timeout support
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "any" else None,
                filter=self.bpf_filter or None,
                prn=self.packet_callback,
                count=self.count_limit or 0,           # 0 = unlimited (mirrors capture_live count=)
                timeout=self.capture_timeout or None,  # None = unlimited (mirrors capture_live timeout=)
                store=0,
                promisc=False  # Disabled promiscuous mode for Windows Wi-Fi compatibility
            )
            self.sniffer.start()
            logger.info(
                f"Capture session {self.session_id} started on interface {self.interface} "
                f"with BPF '{self.bpf_filter}' "
                f"[count={count_limit or 'unlimited'}, timeout={capture_timeout or 'unlimited'}s]"
            )
            return self.session_id
        except Exception as e:
            self.is_capturing = False
            logger.error(f"Failed to start AsyncSniffer: {e}")
            if self.pcap_writer:
                self.pcap_writer.close()
            if self.temp_pcap_path.exists():
                try:
                    self.temp_pcap_path.unlink()
                except:
                    pass
            raise RuntimeError(f"Sniffer execution failed: {e}")

    def pause_capture(self):
        self.is_paused = True
        logger.info(f"Capture session {self.session_id} paused")

    def resume_capture(self):
        self.is_paused = False
        logger.info(f"Capture session {self.session_id} resumed")

    def stop_capture(self) -> str:
        """Stop capture session, close PCAP writer, generate final report."""
        if not self.is_capturing:
            return ""

        self.is_capturing = False
        session_id = self.session_id

        if hasattr(self, "simulation_task") and self.simulation_task:
            try:
                self.simulation_task.cancel()
            except:
                pass
            self.simulation_task = None

        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.error(f"Error stopping AsyncSniffer: {e}")

        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception as e:
                logger.error(f"Error closing PCAP writer: {e}")

        logger.info(f"Capture session {session_id} stopped. Saved rolling pcap to {self.temp_pcap_path}")

        # --- print_report() equivalent: generate + cache + broadcast final report ---
        self._last_report = self.generate_report()
        self._broadcast_report(self._last_report)

        return session_id

    def get_status(self) -> dict:
        """Get capture state, metrics, and memory usage details."""
        elapsed = time.time() - self.start_time if self.start_time > 0 else 0
        pps = self.packet_count / elapsed if elapsed > 0 else 0
        bps = self.bytes_captured / elapsed if elapsed > 0 else 0

        return {
            "session_id": self.session_id,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "is_capturing": self.is_capturing,
            "is_paused": self.is_paused,
            "filter_private": self.filter_private,
            "count_limit": self.count_limit,
            "capture_timeout": self.capture_timeout,
            "packet_count": self.packet_count,
            "dropped_packets": self.dropped_packets,
            "bytes_captured": self.bytes_captured,
            "elapsed_seconds": int(elapsed),
            "pps": round(pps, 2),
            "bps": round(bps, 2),
            "ring_buffer_size": len(self.display_ring_buffer),
            "ring_buffer_memory_mb": round(self.ring_buffer_bytes / (1024*1024), 2),
            "queue_depth": packet_bridge.get_queue_depth(),
            "backpressure_ratio": round(packet_bridge.get_backpressure_ratio(), 4)
        }

    def packet_callback(self, packet: Packet):
        """Called by Scapy Sniffer for each packet captured."""
        logger.info(f"packet_callback entered. is_capturing={self.is_capturing}, is_paused={self.is_paused}")
        if self.is_paused or not self.is_capturing:
            return
            
        try:
            # 1. Backpressure and VoIP Prioritization Mechanism
            backpressure = packet_bridge.get_backpressure_ratio()
            if backpressure > 0.90:
                from scapy.layers.inet import IP, UDP, TCP
                is_voip = False
                if IP in packet:
                    ip_layer = packet[IP]
                    if UDP in ip_layer:
                        sport = ip_layer[UDP].sport
                        dport = ip_layer[UDP].dport
                        if sport in (5060, 5061, 3478, 3479, 5349) or dport in (5060, 5061, 3478, 3479, 5349) or (10000 <= sport <= 20000) or (10000 <= dport <= 20000):
                            is_voip = True
                    elif TCP in ip_layer:
                        sport = ip_layer[TCP].sport
                        dport = ip_layer[TCP].dport
                        if sport in (5060, 5061) or dport in (5060, 5061):
                            is_voip = True
                
                if not is_voip:
                    self.dropped_packets += 1
                    logger.info("Dropping non-VoIP packet due to backpressure.")
                    return
                else:
                    # Let the thread sleep briefly to absorb burst for VoIP packets
                    time.sleep(0.01)

            self.packet_count += 1
            length = len(packet)
            self.bytes_captured += length
                
            # 2. Write to rolling PCAP file
            if self.pcap_writer:
                self.pcap_writer.write(packet)
                
            # 3. Add to display ring buffer
            # Estimate memory size (rough size of packet dictionary + metadata)
            est_size = length + 500  # packet size + dict overhead
            self.display_ring_buffer.append((est_size, packet))
            self.ring_buffer_bytes += est_size
            
            # Enforce 256MB memory cap
            while self.ring_buffer_bytes > self.max_memory_bytes and self.display_ring_buffer:
                item_size, _ = self.display_ring_buffer.popleft()
                self.ring_buffer_bytes -= item_size
                
            # 4. Queue packet into the bridge for asynchronous flow processing & websocket broadcast
            # Pass packet bytes + metadata so it is parsed in the bridge's loop
            pkt_raw = bytes(packet)
            pkt_meta = {
                "timestamp": time.time(),
                "length": length,
                "raw_bytes": pkt_raw
            }
            logger.info(f"Queueing packet index {self.packet_count} into packet_bridge...")
            packet_bridge.queue_packet(pkt_meta)
            
            # 5. Periodically write session statistics to database
            now = time.time()
            if now - self.last_stats_write > 5.0:
                self.last_stats_write = now
                self.write_session_stats()
            
        except Exception as e:
            logger.error(f"Error in capture packet callback: {e}")

    def write_session_stats(self):
        """Periodically writes capture session stats to live_capture.sqlite3."""
        if not self.session_id:
            return
        try:
            elapsed = time.time() - self.start_time if self.start_time > 0 else 0
            pps = self.packet_count / elapsed if elapsed > 0 else 0
            bps = self.bytes_captured / elapsed if elapsed > 0 else 0
            
            router.execute(
                "capture_statistics",
                """INSERT INTO capture_statistics 
                (timestamp, packet_count, dropped_packets, packets_per_second, bytes_per_second)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    self.packet_count, self.dropped_packets,
                    round(pps, 2), round(bps, 2)
                )
            )
        except Exception as e:
            logger.error(f"Failed to write session statistics to database: {e}")

    def promote_to_investigation(self) -> str:
        """Promotes the active rolling PCAP file to a formal investigation record."""
        if not self.temp_pcap_path or not self.temp_pcap_path.exists():
            raise FileNotFoundError("No active capture session or temporary PCAP file found to promote.")
            
        # Ensure Sniffer is stopped
        self.stop_capture()
        
        # We return the path of the PCAP file. The API layer (app/main.py) will process it 
        # using the existing PCAP parsing pipeline to populate investigations.sqlite3.
        return str(self.temp_pcap_path)

    def handle_sigterm(self, signum, frame):
        logger.info(f"SIGTERM received. finalising capture session cleanly.")
        self.shutdown()

    def shutdown(self):
        """Zero-packet-loss shutdown handler."""
        if self.is_capturing:
            logger.info("Atexit/Shutdown triggered. Stopping capture...")
            self.stop_capture()
            # Flush any pending bridge queue tasks
            packet_bridge.stop()

    # =========================================================================
    # Report generation — mirrors print_report() from ProductionWebRTCCaptureEngine v3
    # =========================================================================

    def generate_report(self) -> dict:
        """
        Build a structured final capture report equivalent to print_report().

        Pulls data from voip_manager.ip_store (categorised IPs),
        voip_manager.turn_allocations, and voip_manager.ice_state_machines.

        Returns a dict that mirrors the print_report() output sections:
          - capture_results   : {SIP Via, Contact, SDP IP, SRFLX, RTP} first-seen IPs
          - turn_allocations  : relay/client/lifetime/channels per allocation
          - ice_sessions      : ufrag -> {state, nominated} per ICE session
          - extracted_ips     : full de-duplicated list with confidence/source
          - total_ips         : total extraction count
          - session_stats     : packet_count, dropped, elapsed, bytes
        """
        try:
            from app.protocols.voip_manager import voip_manager
        except Exception:
            voip_manager = None

        elapsed = time.time() - self.start_time if self.start_time > 0 else 0

        # --- Section 1: Categorised IP results (mirrors "--- CAPTURE RESULTS ---") ---
        capture_results = {
            "SIP Via": "N/A",
            "Contact": "N/A",
            "SDP IP": "N/A",
            "SRFLX": "N/A",
            "RTP": "N/A",
        }
        extracted_ips_list = []
        total_ips = 0

        if voip_manager:
            categories = voip_manager.ip_store.get_by_category()
            for label in capture_results:
                if label in categories and categories[label]:
                    capture_results[label] = categories[label]

            extracted_ips_list = [
                {
                    "source": e.source,
                    "ip": e.ip,
                    "port": e.port,
                    "ip_version": e.ip_version,
                    "confidence": e.confidence,
                    "session_id": e.session_id,
                    "is_nominated": e.is_nominated,
                    "context": e.context,
                    "timestamp": e.timestamp,
                }
                for e in voip_manager.ip_store.extracted_ips
            ]
            total_ips = len(voip_manager.ip_store.extracted_ips)

        # --- Section 2: TURN allocations (mirrors "[TURN ALLOCATIONS]") ---
        turn_allocations = []
        if voip_manager:
            for key, alloc in voip_manager.turn_allocations.items():
                turn_allocations.append({
                    "relay": key,
                    "client_addr": alloc.client_addr,
                    "client_port": alloc.client_port,
                    "lifetime": alloc.lifetime,
                    "realm": alloc.realm,
                    "channel_count": len(alloc.channels),
                    "channels": {
                        str(ch): f"{peer[0]}:{peer[1]}"
                        for ch, peer in alloc.channels.items()
                    },
                })

        # --- Section 3: ICE sessions (mirrors "[ICE Sessions: N]") ---
        ice_sessions = []
        if voip_manager:
            for ufrag, machine in voip_manager.ice_state_machines.items():
                pair = machine.nominated_pair
                ice_sessions.append({
                    "ufrag": ufrag,
                    "state": machine.ice_state.name,
                    "nominated": machine.nomination_confirmed,
                    "nominated_pair": {
                        "local_ip": pair.local_candidate.ip,
                        "local_port": pair.local_candidate.port,
                        "remote_ip": pair.remote_candidate.ip,
                        "remote_port": pair.remote_candidate.port,
                    } if pair else None,
                    "checks_total": len(machine.checks),
                    "is_controlling": machine.is_controlling,
                })

        # --- Section 4: Session stats ---
        report = {
            "session_id": self.session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "filter_private": self.filter_private,
            "capture_results": capture_results,
            "turn_allocations": turn_allocations,
            "ice_sessions": ice_sessions,
            "extracted_ips": extracted_ips_list,
            "total_ips": total_ips,
            "session_stats": {
                "packet_count": self.packet_count,
                "dropped_packets": self.dropped_packets,
                "bytes_captured": self.bytes_captured,
                "elapsed_seconds": round(elapsed, 2),
            },
        }

        # Log summary to console/logger — mirrors print_report() print block
        logger.info("=" * 60)
        logger.info("PRODUCTION WEBRTC CAPTURE REPORT")
        logger.info("=" * 60)
        logger.info("--- CAPTURE RESULTS ---")
        for label, ip in capture_results.items():
            logger.info(f"  {label:12s}: {ip}")
        logger.info("-" * 22)
        if turn_allocations:
            logger.info(f"[TURN ALLOCATIONS: {len(turn_allocations)}]")
            for a in turn_allocations:
                logger.info(f"  Relay : {a['relay']}")
                logger.info(f"    Client  : {a['client_addr']}:{a['client_port']}")
                logger.info(f"    Channels: {a['channel_count']}")
                for ch, peer in a['channels'].items():
                    logger.info(f"      ch{ch} -> {peer}")
        logger.info(f"[ICE Sessions: {len(ice_sessions)}]")
        for sess in ice_sessions:
            nominated = "YES" if sess["nominated"] else "NO"
            logger.info(f"  {sess['ufrag']}: {sess['state']}, nominated={nominated}")
        logger.info(f"[Total IPs extracted: {total_ips}]")

        return report

    def get_report(self) -> dict | None:
        """
        Return the last generated report (produced on stop_capture()).
        If capture is still running, generates a live snapshot report.
        """
        if self.is_capturing:
            # Live snapshot during capture
            return self.generate_report()
        return self._last_report

    def _broadcast_report(self, report: dict):
        """
        Broadcast the final capture report over WebSocket.
        This is the async equivalent of print_report() — pushes structured
        data to the frontend instead of printing to stdout.
        """
        try:
            import asyncio
            from app.core.bridge import broadcast_manager

            async def _do_broadcast():
                await broadcast_manager.broadcast({
                    "type": "capture_report",
                    "report": report
                }, priority=1)

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_do_broadcast())
            except RuntimeError:
                asyncio.run(_do_broadcast())
        except Exception as e:
            logger.error(f"Failed to broadcast capture report: {e}")

    async def run_simulation(self):
        """Asynchronously generates realistic testing traffic packets to push into event bridge."""
        import random
        import asyncio
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.dns import DNS, DNSQR
        from scapy.packet import Packet
        
        local_ips = ["192.168.1.15", "192.168.1.22", "192.168.1.50", "192.168.1.99"]
        external_ips = ["8.8.8.8", "1.1.1.1", "104.244.42.1", "142.250.190.46", "185.199.108.153"]
        dns_queries = ["google.com", "github.com", "slack.com", "aws.amazon.com", "malicious-c2-beacon.net"]
        
        sip_state = 0
        sip_call_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
        sip_src = "192.168.1.50"
        sip_dst = "192.168.1.22"
        rtp_packets_sent = 0
        
        while self.is_capturing:
            if self.is_paused:
                await asyncio.sleep(0.5)
                continue
                
            try:
                choice = random.random()
                pkt = None
                
                # A. DNS Query
                if choice < 0.15:
                    src = random.choice(local_ips)
                    query = random.choice(dns_queries)
                    pkt = IP(src=src, dst="8.8.8.8")/UDP(sport=random.randint(49152, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=query))
                    
                # B. HTTP Plaintext Password Leak (DPI alert trigger)
                elif choice < 0.25:
                    src = random.choice(local_ips)
                    dst = random.choice(external_ips)
                    payload = f"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin&password=SuperSecretPassword123!"
                    pkt = IP(src=src, dst=dst)/TCP(sport=random.randint(49152, 65535), dport=80)/payload
                    
                # C. C2 Beaconing (Regular TCP Connects)
                elif choice < 0.40:
                    pkt = IP(src="192.168.1.50", dst="104.244.42.1")/TCP(sport=50555, dport=443, flags="S")
                    
                # D. VoIP Loop simulation
                elif choice < 0.85:
                    if sip_state == 0:
                        payload = f"INVITE sip:bob@192.168.1.22 SIP/2.0\r\nCall-ID: {sip_call_id}\r\nFrom: alice <sip:alice@192.168.1.50>\r\nTo: bob <sip:bob@192.168.1.22>\r\nContent-Length: 120\r\n\r\n"
                        pkt = IP(src=sip_src, dst=sip_dst)/UDP(sport=5060, dport=5060)/payload
                        sip_state = 1
                    elif sip_state == 1:
                        payload = f"SIP/2.0 180 Ringing\r\nCall-ID: {sip_call_id}\r\nFrom: alice <sip:alice@192.168.1.50>\r\nTo: bob <sip:bob@192.168.1.22>\r\nContent-Length: 0\r\n\r\n"
                        pkt = IP(src=sip_dst, dst=sip_src)/UDP(sport=5060, dport=5060)/payload
                        sip_state = 2
                    elif sip_state == 2:
                        payload = f"SIP/2.0 200 OK\r\nCall-ID: {sip_call_id}\r\nFrom: alice <sip:alice@192.168.1.50>\r\nTo: bob <sip:bob@192.168.1.22>\r\nContent-Length: 100\r\n\r\n"
                        pkt = IP(src=sip_dst, dst=sip_src)/UDP(sport=5060, dport=5060)/payload
                        sip_state = 3
                    elif sip_state == 3:
                        payload = f"ACK sip:bob@192.168.1.22 SIP/2.0\r\nCall-ID: {sip_call_id}\r\nFrom: alice <sip:alice@192.168.1.50>\r\nTo: bob <sip:bob@192.168.1.22>\r\nContent-Length: 0\r\n\r\n"
                        pkt = IP(src=sip_src, dst=sip_dst)/UDP(sport=5060, dport=5060)/payload
                        sip_state = 4
                        rtp_packets_sent = 0
                    elif sip_state == 4:
                        rtp_header = b"\x80\x00\x00\x01\x00\x00\x00\x00\x07\x5b\xcd\x15"
                        pkt = IP(src=sip_src, dst=sip_dst)/UDP(sport=16384, dport=16384)/rtp_header
                        rtp_packets_sent += 1
                        if rtp_packets_sent > 30:
                            sip_state = 5
                    elif sip_state == 5:
                        payload = f"BYE sip:bob@192.168.1.22 SIP/2.0\r\nCall-ID: {sip_call_id}\r\nFrom: alice <sip:alice@192.168.1.50>\r\nTo: bob <sip:bob@192.168.1.22>\r\nContent-Length: 0\r\n\r\n"
                        pkt = IP(src=sip_src, dst=sip_dst)/UDP(sport=5060, dport=5060)/payload
                        sip_state = 0
                        
                # E. TLS Client Hello Client Handshake
                else:
                    src = random.choice(local_ips)
                    dst = random.choice(external_ips)
                    tls_hello = b"\x16\x03\x01\x00\x2d\x01\x00\x00\x29\x03\x03" + b"\x00" * 32
                    pkt = IP(src=src, dst=dst)/TCP(sport=random.randint(49152, 65535), dport=443)/tls_hello
                
                if pkt:
                    scapy_pkt = Packet(bytes(pkt))
                    self.packet_callback(scapy_pkt)
                    
            except Exception as ex:
                logger.error(f"Error in simulated packet generation: {ex}")
                
            await asyncio.sleep(0.05)

# Singleton
capture_manager = LiveCaptureManager()
