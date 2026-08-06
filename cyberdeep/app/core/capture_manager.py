import os
import time
import struct
import threading
import collections
import logging
import queue as queue_mod
from pathlib import Path
import tempfile
import atexit
import signal
from datetime import datetime, timezone
from scapy.sendrecv import AsyncSniffer
from scapy.arch.common import compile_filter
from scapy.utils import PcapWriter
from scapy.packet import Packet, Raw
from scapy.arch import get_if_list
from scapy.all import conf as scapy_conf
from scapy.layers.inet import IP, UDP, TCP

# Configure Scapy socket buffer size for maximum high-speed Gbps capture (64 MB kernel buffer)
scapy_conf.bufsize = 64 * 1024 * 1024

from app.core.config import DATA_DIR
from app.core.bridge import packet_bridge
from app.storage.database import router

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
DEFAULT_BPF_FILTER = "ip or ip6"
_IFACE_CACHE_TTL = 30.0

TEMP_PCAP_DIR = DATA_DIR / "uploads"
TEMP_PCAP_DIR.mkdir(parents=True, exist_ok=True)

# VoIP port set for fast raw-byte prioritization
_VOIP_UDP_PORTS = frozenset({5060, 5061, 3478, 3479, 5349, 19302})
_VOIP_TCP_PORTS = frozenset({5060, 5061})


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
        self.simulation_task = None

        # capture_live() options
        self.filter_private: bool = False
        self.count_limit: int = 0
        self.capture_timeout: int | None = None
        self._last_report: dict | None = None

        # Display Ring Buffer — stores size estimates only (no packet bytes)
        self.display_ring_buffer = collections.deque()
        self.ring_buffer_bytes = 0
        self.max_memory_bytes = 256 * 1024 * 1024  # 256 MB

        # Telemetry — written ONLY by consumer thread, read by API thread
        self._stats_lock = threading.Lock()
        self.packet_count = 0
        self.dropped_packets = 0          # dropped from processing pipeline (never from PCAP)
        self.dropped_kernel = 0           # emergency drops (queue full — packet discarded, see packet_callback)
        self.start_time = 0
        self.bytes_captured = 0
        self.last_stats_write = 0
        self.tcp_retransmissions = 0      # detected by off-path rtx analyzer thread
        self.dropped_rtx_analysis = 0    # packets silently dropped from rtx analysis queue when full

        # Interface list TTL cache
        self._iface_cache: list | None = None
        self._iface_cache_ts: float = 0.0

        # ── ZERO-DROP ARCHITECTURE ──────────────────────────────────────────
        # Ultra-large capture queue: 200K items ≈ 40s @ 5K pps burst capacity
        self._capture_queue: queue_mod.Queue = queue_mod.Queue(maxsize=200_000)
        self._consumer_thread: threading.Thread | None = None
        self._consumer_running: bool = False

        # ── OFF-PATH RTX ANALYZER ────────────────────────────────────────────
        # Bounded queue; drop-on-full is intentional — analyzed via dropped_rtx_analysis
        self._rtx_queue: queue_mod.Queue = queue_mod.Queue(maxsize=10_000)
        self._rtx_thread: threading.Thread | None = None
        self._rtx_running: bool = False

        # ── DIAGNOSTIC INSTRUMENTATION ───────────────────────────────────────
        self._diag_enabled: bool = False
        self._diag_log_path: str | None = None

        # Register atexit and signal handlers
        atexit.register(self.shutdown)
        try:
            signal.signal(signal.SIGTERM, self.handle_sigterm)
        except ValueError:
            pass

    def get_interfaces(self) -> list[dict]:
        """Get available network interfaces with friendly descriptions (TTL-cached for 30s)."""
        now = time.time()
        if self._iface_cache is not None and (now - self._iface_cache_ts) < _IFACE_CACHE_TTL:
            return self._iface_cache

        interfaces = []
        try:
            try:
                scapy_conf.ifaces.reload()
            except Exception as reload_err:
                logger.error(f"Error reloading Scapy interfaces: {reload_err}")
            for iface_name, iface in scapy_conf.ifaces.items():
                desc = iface.description or iface.name
                ip_addr = iface.ip or "No IP"
                is_active = (iface.ip and iface.ip != "0.0.0.0") or "loopback" in iface.name.lower()
                interfaces.append({
                    "id": iface.network_name or iface_name,
                    "name": iface.name,
                    "description": f"{iface.name} ({desc})",
                    "ip": ip_addr,
                    "is_active": is_active
                })
            interfaces.sort(key=lambda x: not x["is_active"])
        except Exception as e:
            logger.error(f"Error listing network interfaces: {e}")
            interfaces = [{"id": "any", "name": "any", "description": "All Interfaces (Any)", "ip": "0.0.0.0", "is_active": True}]

        self._iface_cache = interfaces
        self._iface_cache_ts = now
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
        promiscuous: bool = False,
    ) -> str:
        if self.is_capturing:
            raise ValueError("Capture already in progress")

        if not bpf_filter:
            bpf_filter = DEFAULT_BPF_FILTER

        if bpf_filter and not self.validate_filter(bpf_filter):
            raise ValueError(f"Malformed BPF filter expression: {bpf_filter}")

        self.filter_private = filter_private
        self.count_limit = count_limit
        self.capture_timeout = capture_timeout
        self._last_report = None

        try:
            from app.protocols.voip_manager import voip_manager
            voip_manager.ip_store.filter_private = filter_private
        except Exception:
            pass

        self._cleanup_old_pcap_files(keep=20)
        self.session_id = f"live_{int(time.time())}"
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.temp_pcap_path = TEMP_PCAP_DIR / f"cyberdeep_{self.session_id}.pcap"

        self.display_ring_buffer.clear()
        self.ring_buffer_bytes = 0
        self.packet_count = 0
        self.dropped_packets = 0
        self.dropped_kernel = 0
        self.bytes_captured = 0
        self.tcp_retransmissions = 0
        self.dropped_rtx_analysis = 0
        self.start_time = time.time()

        logger.info("[*] Enterprise Zero-Drop capture engine starting...")
        logger.info(f"[*] Interface       : {interface}")
        logger.info(f"[*] BPF Filter      : {bpf_filter}")
        logger.info(f"[*] Queue Size      : 200,000 items")

        try:
            self.pcap_writer = PcapWriter(str(self.temp_pcap_path), append=True, sync=False)
        except Exception as e:
            logger.error(f"Failed to create PCAP writer at {self.temp_pcap_path}: {e}")
            raise RuntimeError(f"Failed to initialize PCAP output: {e}")

        # Start consumer thread
        self._consumer_running = True
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop, daemon=True, name="pkt-consumer"
        )
        self._consumer_thread.start()

        # Start off-path RTX analyzer thread
        self._rtx_running = True
        self._rtx_thread = threading.Thread(
            target=self._rtx_analyzer_loop, daemon=True, name="rtx-analyzer"
        )
        self._rtx_thread.start()

        # Enable per-session diagnostic instrumentation
        self._diag_log_path = str(DATA_DIR / f"diag_{self.session_id}.log")
        self._diag_enabled = True

        self.is_capturing = True
        self.is_paused = False

        if interface == "simulated":
            import asyncio as _asyncio
            try:
                loop = _asyncio.get_running_loop()
                self.simulation_task = loop.create_task(self.run_simulation())
            except RuntimeError:
                import threading as _threading
                def thread_target():
                    _asyncio.run(self.run_simulation())
                self.simulation_thread = _threading.Thread(target=thread_target, daemon=True)
                self.simulation_thread.start()
            logger.info(f"Simulated capture session {self.session_id} started.")
            return self.session_id

        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "any" else None,
                filter=self.bpf_filter or None,
                prn=self.packet_callback,
                count=self.count_limit or 0,
                timeout=self.capture_timeout or None,
                store=0,
                promisc=promiscuous
            )
            self.sniffer.start()
            logger.info(f"Capture session {self.session_id} started on interface {self.interface}")
        except Exception as e:
            self.is_capturing = False
            self._consumer_running = False
            if self.pcap_writer:
                self.pcap_writer.close()
            if self.temp_pcap_path.exists():
                try:
                    self.temp_pcap_path.unlink()
                except Exception:
                    pass
            raise RuntimeError(f"Sniffer execution failed: {e}")

        return self.session_id

    # ── HOT PATH: Sniffer Thread ──────────────────────────────────────────────
    # Target execution time: < 2 microseconds per packet.
    # ONLY serializes to raw bytes once and enqueues to _capture_queue.
    # ZERO disk I/O, ZERO lock acquisition, ZERO logging.
    def packet_callback(self, packet: Packet):
        if self.is_paused or not self.is_capturing:
            return
        try:
            raw_pkt = bytes(packet)
            pkt_time = time.time()
            pkt_len = len(raw_pkt)
            self._capture_queue.put_nowait((raw_pkt, pkt_time, pkt_len))
        except queue_mod.Full:
            # Queue is full — increment counter and discard.
            # Do NOT write to PCAP here: any disk I/O on the sniffer callback thread
            # blocks socket.recv(), starves the libpcap socket buffer, and directly
            # causes multi-second capture gaps. At 200K items and observed rates (~80 pps)
            # the queue filling at all indicates a deeper pipeline problem worth diagnosing
            # separately rather than papering over with an inline write.
            with self._stats_lock:
                self.dropped_kernel += 1

    # ── CONSUMER THREAD: Drains capture_queue off sniffer thread ──────────────
    def _consumer_loop(self):
        logger.info("[*] Capture consumer thread started.")

        # Open per-session diagnostic log — written only on anomalies, zero overhead on happy path.
        # Three probe points per packet:
        #   T0 = packet_callback timestamp (kernel→Python boundary, captured on sniffer thread)
        #   T1 = time of dequeue from _capture_queue (measures queue wait: T1 - T0)
        #   T2 = time after pcap_writer.write() returns (measures write latency: T2 - T1)
        # Gap in T0 inter-arrivals > threshold → sniffer thread stalled (GIL or libpcap).
        # Large T1-T0 → consumer thread falling behind, queue backing up.
        # Large T2-T1 → PCAP write is the bottleneck.
        diag_file = None
        if self._diag_enabled and self._diag_log_path:
            try:
                diag_file = open(self._diag_log_path, "w", buffering=1)
                diag_file.write("# Anomalies only: gap>0.5s inter-arrival | wait>50ms queue | write>50ms disk\n")
                diag_file.write("# T0=callback_ts(s) gap=inter-arrival(s) wait=queue_wait(s) write=disk_write(s)\n")
            except Exception as exc:
                logger.warning(f"Could not open diagnostic log {self._diag_log_path}: {exc}")

        prev_t0: float | None = None

        while self._consumer_running or not self._capture_queue.empty():
            try:
                item = self._capture_queue.get(timeout=0.1)
            except queue_mod.Empty:
                continue

            t1 = time.time()   # T1: dequeue time

            if item is None:
                break

            raw_pkt, pkt_time, pkt_len = item  # pkt_time is T0 (set in packet_callback)

            # 1. Stats + ring buffer — single lock acquisition per packet
            est_size = pkt_len + 500
            self.display_ring_buffer.append(est_size)
            with self._stats_lock:
                self.packet_count += 1
                self.bytes_captured += pkt_len
                self.ring_buffer_bytes += est_size

            # Evict oldest ring-buffer entries when over memory limit;
            # accumulate evictions and apply in one lock to avoid repeated acquisitions.
            if self.ring_buffer_bytes > self.max_memory_bytes:
                evict_bytes = 0
                while (self.ring_buffer_bytes - evict_bytes > self.max_memory_bytes
                       and self.display_ring_buffer):
                    evict_bytes += self.display_ring_buffer.popleft()
                if evict_bytes:
                    with self._stats_lock:
                        self.ring_buffer_bytes -= evict_bytes

            # 2. Write to PCAP
            if self.pcap_writer:
                try:
                    self.pcap_writer.write(raw_pkt)
                except Exception as e:
                    logger.error(f"Error writing to PCAP: {e}")

            t2 = time.time()   # T2: post-write time

            # 3. Diagnostic — log anomalies only
            if diag_file and prev_t0 is not None:
                gap       = pkt_time - prev_t0   # inter-arrival at sniffer thread
                wait      = t1 - pkt_time        # time spent in queue
                write_lat = t2 - t1              # PCAP write latency
                if gap > 0.5 or wait > 0.05 or write_lat > 0.05:
                    try:
                        diag_file.write(
                            f"T0={pkt_time:.6f} gap={gap:.4f}s "
                            f"wait={wait:.4f}s write={write_lat:.4f}s\n"
                        )
                    except Exception:
                        pass
            prev_t0 = pkt_time

            # 4. Check packet_bridge backpressure with fast VoIP prioritization
            backpressure = packet_bridge.get_backpressure_ratio()
            if backpressure > 0.90:
                is_voip = self._fast_is_voip(raw_pkt)
                if not is_voip:
                    with self._stats_lock:
                        self.dropped_packets += 1
                    self._capture_queue.task_done()
                    continue

            # 5. Feed RTX analyzer — single non-blocking put; TCP packets only.
            #    dropped_rtx_analysis distinguishes queue-full silence from genuine clean traffic.
            tcp_meta = self._extract_tcp_meta(raw_pkt)
            if tcp_meta is not None:
                try:
                    self._rtx_queue.put_nowait(tcp_meta)
                except queue_mod.Full:
                    with self._stats_lock:
                        self.dropped_rtx_analysis += 1

            # 6. Queue into bridge for async processing
            packet_bridge.queue_packet({
                "timestamp": pkt_time,
                "length": pkt_len,
                "raw_bytes": raw_pkt,
            })
            self._capture_queue.task_done()

            # 7. Periodic stats write to DB
            if pkt_time - self.last_stats_write > 5.0:
                self.last_stats_write = pkt_time
                self.write_session_stats()

        if diag_file:
            try:
                diag_file.close()
            except Exception:
                pass
        logger.info("[*] Capture consumer thread stopped.")

    def _fast_is_voip(self, raw_pkt: bytes) -> bool:
        """Fast raw-byte parsing for VoIP ports (SIP/STUN/TURN) without Scapy overhead."""
        if len(raw_pkt) < 34:
            return False
        # Check IP version (IPv4 = 0x4)
        if (raw_pkt[0] >> 4) == 4:
            proto = raw_pkt[9]
            if proto == 17:  # UDP
                if len(raw_pkt) >= 42:
                    sport, dport = struct.unpack("!HH", raw_pkt[34:38])
                    return sport in _VOIP_UDP_PORTS or dport in _VOIP_UDP_PORTS or (10000 <= sport <= 20000) or (10000 <= dport <= 20000)
            elif proto == 6:  # TCP
                if len(raw_pkt) >= 54:
                    sport, dport = struct.unpack("!HH", raw_pkt[34:38])
                    return sport in _VOIP_TCP_PORTS or dport in _VOIP_TCP_PORTS
        return False

    def _extract_tcp_meta(self, raw_pkt: bytes):
        """
        Fast raw-byte extraction of TCP fields for the off-path retransmission analyzer.
        Returns (src, dst, sport, dport, seq, flags, payload_len) or None.
        Handles Ethernet + IPv4 + TCP only; IPv6 and tunnels are silently skipped.
        """
        if len(raw_pkt) < 34:
            return None
        # Ethernet type at offset 12
        if raw_pkt[12] != 0x08 or raw_pkt[13] != 0x00:  # not IPv4
            return None
        proto = raw_pkt[23]
        if proto != 6:                                    # not TCP
            return None
        ihl        = (raw_pkt[14] & 0x0F) * 4
        ip_offset  = 14
        tcp_offset = ip_offset + ihl
        if len(raw_pkt) < tcp_offset + 20:
            return None
        src  = raw_pkt[ip_offset + 12: ip_offset + 16]
        dst  = raw_pkt[ip_offset + 16: ip_offset + 20]
        sport, dport  = struct.unpack_from("!HH", raw_pkt, tcp_offset)
        seq,          = struct.unpack_from("!I",  raw_pkt, tcp_offset + 4)
        data_off      = ((raw_pkt[tcp_offset + 12] >> 4) & 0xF) * 4
        flags         = raw_pkt[tcp_offset + 13]
        ip_total_len, = struct.unpack_from("!H",  raw_pkt, ip_offset + 2)
        payload_len   = max(0, ip_total_len - ihl - data_off)
        return (bytes(src), bytes(dst), sport, dport, seq, flags, payload_len)

    def _rtx_analyzer_loop(self):
        """
        Off-hot-path TCP retransmission detector running in its own daemon thread.

        Design:
        - Fed via _rtx_queue with non-blocking put_nowait(); drop-on-full is intentional.
          dropped_rtx_analysis counter distinguishes queue-full silence from clean traffic.
        - Modular 32-bit sequence arithmetic (RFC 793 §3.3) handles wraparound correctly:
          seq is a retransmission iff it is strictly "before" expected_next_seq in the
          circular sequence space, i.e. (expected - seq) & 0xFFFF_FFFF < 0x8000_0000.
        - Per-flow state dict with TTL-based eviction + FIN/RST teardown bounds memory
          growth on long captures with many short-lived connections.
        - Rate-limited WARNING log when retransmission rate exceeds 1% of TCP segments.
        """
        logger.info("[*] RTX analyzer thread started.")

        # flow_state: (src, dst, sport, dport) -> (expected_next_seq, last_seen_ts, fin_seen)
        flow_state: dict = {}
        EVICT_INTERVAL   = 60.0   # seconds between eviction sweeps
        IDLE_TTL         = 120.0  # evict flows idle longer than this
        last_evict       = time.time()

        FLAG_SYN = 0x02
        FLAG_RST = 0x04
        FLAG_FIN = 0x01

        tcp_total  = 0
        rtx_count  = 0
        last_alert = 0.0
        ALERT_MIN_INTERVAL = 30.0  # suppress repeated alerts within this window

        while self._rtx_running:
            try:
                item = self._rtx_queue.get(timeout=0.2)
            except queue_mod.Empty:
                # Still perform eviction sweeps during idle traffic
                now = time.time()
                if now - last_evict > EVICT_INTERVAL:
                    self._evict_idle_flows(flow_state, now, IDLE_TTL)
                    last_evict = now
                continue

            if item is None:
                break

            src, dst, sport, dport, seq, flags, payload_len = item
            now = time.time()
            key = (src, dst, sport, dport)

            # --- Retransmission detection (payload-bearing segments only) ---
            if payload_len > 0:
                tcp_total += 1
                if key in flow_state:
                    expected, _, _ = flow_state[key]
                    # Modular comparison: seq is "before" expected iff
                    # (expected - seq) mod 2^32 < 2^31 and seq != expected.
                    # Plain seq < expected misfires on every wraparound past 2^32.
                    delta = (expected - seq) & 0xFFFFFFFF
                    if seq != expected and delta < 0x80000000:
                        # seq lies behind expected_next_seq → retransmission
                        rtx_count += 1
                        with self._stats_lock:
                            self.tcp_retransmissions += 1
                        # Rate-limited alert
                        if tcp_total >= 100:
                            rate = rtx_count / tcp_total
                            if rate > 0.01 and now - last_alert > ALERT_MIN_INTERVAL:
                                logger.warning(
                                    f"[RTX] Retransmission rate {rate * 100:.1f}% "
                                    f"({rtx_count}/{tcp_total} TCP segments). "
                                    f"Analysis queue dropped: {self.dropped_rtx_analysis}"
                                )
                                last_alert = now
                    else:
                        # Normal or out-of-order: advance expected next seq
                        new_exp = (seq + payload_len) & 0xFFFFFFFF
                        _, ts, fin = flow_state[key]
                        flow_state[key] = (new_exp, now, fin)
                else:
                    # New flow — record initial state
                    new_exp = (seq + payload_len) & 0xFFFFFFFF
                    flow_state[key] = (new_exp, now, False)

            # --- Flow teardown on RST / FIN ---
            if flags & FLAG_RST:
                flow_state.pop(key, None)
            elif flags & FLAG_FIN:
                if key in flow_state:
                    exp, _, _ = flow_state[key]
                    flow_state[key] = (exp, now, True)

            # --- Periodic eviction sweep ---
            if now - last_evict > EVICT_INTERVAL:
                self._evict_idle_flows(flow_state, now, IDLE_TTL)
                last_evict = now

            self._rtx_queue.task_done()

        logger.info(
            f"[*] RTX analyzer stopped. "
            f"TCP segments: {tcp_total}, Retransmissions: {rtx_count}, "
            f"Dropped from analysis queue: {self.dropped_rtx_analysis}"
        )

    @staticmethod
    def _evict_idle_flows(flow_state: dict, now: float, idle_ttl: float) -> None:
        """Remove flow-state entries idle longer than idle_ttl seconds."""
        stale = [k for k, (_, ts, _) in flow_state.items() if now - ts > idle_ttl]
        for k in stale:
            del flow_state[k]
        if stale:
            logger.debug(f"[RTX] Evicted {len(stale)} idle flows; {len(flow_state)} remain.")

    def stop_capture(self) -> dict:
        if not self.is_capturing:
            return self.get_status()

        logger.info("Stopping capture session...")
        self.is_capturing = False

        if self.simulation_task:
            try:
                self.simulation_task.cancel()
            except Exception:
                pass
            self.simulation_task = None

        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.error(f"Error stopping AsyncSniffer: {e}")
            self.sniffer = None

        # Stop consumer and drain queue
        self._consumer_running = False
        if self._consumer_thread and self._consumer_thread.is_alive():
            self._capture_queue.put(None)
            self._consumer_thread.join(timeout=5.0)

        # Stop RTX analyzer
        self._rtx_running = False
        if self._rtx_thread and self._rtx_thread.is_alive():
            try:
                self._rtx_queue.put_nowait(None)
            except queue_mod.Full:
                pass
            self._rtx_thread.join(timeout=3.0)

        # Disable diagnostics and log location for operator reference
        self._diag_enabled = False
        if self._diag_log_path:
            logger.info(f"[*] Diagnostic log: {self._diag_log_path} "
                        f"(inspect for T0 gaps, queue wait, write latency)")

        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception as e:
                logger.error(f"Error closing PCAP writer: {e}")
            self.pcap_writer = None

        report = self.generate_report()
        self._last_report = report
        self._broadcast_report(report)

        self._cleanup_old_pcap_files(keep=20)
        logger.info(
            f"Capture session {self.session_id} stopped. Total packets: {self.packet_count}, "
            f"Pipeline dropped: {self.dropped_packets}, Emergency dropped: {self.dropped_kernel}"
        )
        return report

    def _cleanup_old_pcap_files(self, keep: int = 20):
        """Keep only the most recent `keep` PCAP files in TEMP_PCAP_DIR, deleting older files to reclaim disk space."""
        try:
            pcap_files = sorted(
                [f for f in TEMP_PCAP_DIR.glob("*.pcap")],
                key=lambda f: f.stat().st_mtime,
                reverse=True
            )
            for old_pcap in pcap_files[keep:]:
                try:
                    old_pcap.unlink(missing_ok=True)
                    logger.info(f"Auto-cleaned old PCAP file: {old_pcap.name}")
                except Exception as e:
                    logger.debug(f"Could not remove old PCAP {old_pcap.name}: {e}")
        except Exception as e:
            logger.error(f"Error during PCAP directory retention cleanup: {e}")

    def pause_capture(self):
        if self.is_capturing and not self.is_paused:
            self.is_paused = True
            logger.info("Capture session paused.")

    def resume_capture(self):
        if self.is_capturing and self.is_paused:
            self.is_paused = False
            logger.info("Capture session resumed.")

    def get_status(self) -> dict:
        elapsed = time.time() - self.start_time if (self.is_capturing and self.start_time > 0) else 0
        with self._stats_lock:
            pkt_cnt         = self.packet_count
            bytes_cnt       = self.bytes_captured
            dropped_cnt     = self.dropped_packets
            kernel_cnt      = self.dropped_kernel
            ring_bytes      = self.ring_buffer_bytes
            ring_len        = len(self.display_ring_buffer)
            rtx_cnt         = self.tcp_retransmissions
            dropped_rtx_cnt = self.dropped_rtx_analysis

        return {
            "session_id": self.session_id,
            "is_capturing": self.is_capturing,
            "is_paused": self.is_paused,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "packet_count": pkt_cnt,
            "dropped_packets": dropped_cnt,
            "dropped_kernel": kernel_cnt,
            "bytes_captured": bytes_cnt,
            "elapsed_seconds": round(elapsed, 2),
            "ring_buffer_size": ring_len,
            "ring_buffer_memory_mb": round(ring_bytes / (1024 * 1024), 2),
            "queue_depth": packet_bridge.get_queue_depth(),
            "capture_queue_depth": self._capture_queue.qsize(),
            "backpressure_ratio": round(packet_bridge.get_backpressure_ratio(), 4),
            "tcp_retransmissions": rtx_cnt,
            "dropped_rtx_analysis": dropped_rtx_cnt,
            "diag_log": self._diag_log_path if self._diag_log_path else None,
        }

    def write_session_stats(self):
        if not self.session_id:
            return
        try:
            elapsed = time.time() - self.start_time if self.start_time > 0 else 0
            with self._stats_lock:
                pkt_cnt = self.packet_count
                bytes_cnt = self.bytes_captured
                dropped_cnt = self.dropped_packets
            pps = pkt_cnt / elapsed if elapsed > 0 else 0
            bps = bytes_cnt / elapsed if elapsed > 0 else 0

            router.execute(
                "capture_statistics",
                """INSERT INTO capture_statistics 
                (timestamp, packet_count, dropped_packets, packets_per_second, bytes_per_second)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    pkt_cnt, dropped_cnt,
                    round(pps, 2), round(bps, 2)
                )
            )
        except Exception as e:
            logger.error(f"Failed to write session statistics to database: {e}")

    def promote_to_investigation(self) -> str:
        if not self.temp_pcap_path or not self.temp_pcap_path.exists():
            raise FileNotFoundError("No active capture session or temporary PCAP file found to promote.")
        self.stop_capture()
        return str(self.temp_pcap_path)

    def handle_sigterm(self, signum, frame):
        logger.info("SIGTERM received. Finalising capture session cleanly.")
        self.shutdown()

    def shutdown(self):
        if self.is_capturing:
            logger.info("Atexit/Shutdown triggered. Stopping capture...")
            self.stop_capture()
            packet_bridge.stop()

    def generate_report(self) -> dict:
        try:
            from app.protocols.voip_manager import voip_manager
        except Exception:
            voip_manager = None

        elapsed = time.time() - self.start_time if self.start_time > 0 else 0

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

        ice_sessions = []
        if voip_manager:
            for key, machine in voip_manager.ice_state_machines.items():
                ice_sessions.append({
                    "ufrag": key,
                    "state": machine.state,
                    "nominated": machine.nominated_pair is not None,
                })

        with self._stats_lock:
            pkt_cnt = self.packet_count
            bytes_cnt = self.bytes_captured
            dropped_cnt = self.dropped_packets

        report = {
            "session_id": self.session_id,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "filter_private": self.filter_private,
            "capture_results": capture_results,
            "extracted_ips": extracted_ips_list,
            "turn_allocations": turn_allocations,
            "ice_sessions": ice_sessions,
            "total_ips": total_ips,
            "session_stats": {
                "packet_count": pkt_cnt,
                "dropped_packets": dropped_cnt,
                "bytes_captured": bytes_cnt,
                "elapsed_seconds": round(elapsed, 2),
            },
        }

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
        if self.is_capturing:
            return self.generate_report()
        return self._last_report

    def _broadcast_report(self, report: dict):
        try:
            import asyncio as _asyncio
            from app.core.bridge import broadcast_manager

            async def _do_broadcast():
                await broadcast_manager.broadcast({
                    "type": "capture_report",
                    "report": report
                }, priority=1)

            try:
                loop = _asyncio.get_running_loop()
                loop.create_task(_do_broadcast())
            except RuntimeError:
                pass
        except Exception as e:
            logger.error(f"Failed to broadcast capture report: {e}")

    async def run_simulation(self):
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
                
                if choice < 0.15:
                    src = random.choice(local_ips)
                    query = random.choice(dns_queries)
                    pkt = IP(src=src, dst="8.8.8.8")/UDP(sport=random.randint(49152, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=query))
                elif choice < 0.25:
                    src = random.choice(local_ips)
                    dst = random.choice(external_ips)
                    payload = f"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin&password=SuperSecretPassword123!"
                    pkt = IP(src=src, dst=dst)/TCP(sport=random.randint(49152, 65535), dport=80)/payload
                elif choice < 0.40:
                    pkt = IP(src="192.168.1.50", dst="104.244.42.1")/TCP(sport=50555, dport=443, flags="S")
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
