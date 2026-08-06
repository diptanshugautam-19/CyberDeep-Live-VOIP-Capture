import time
import json
import logging
import asyncio
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from app.storage.database import router, get_endpoint_id, compress_bytes, calculate_entropy
from app.core.bridge import broadcast_manager
from app.core.fingerprint import get_tls_fingerprints, parse_ssh_hassh
from app.flows.stream_reassembler import stream_reassembler, udp_reconstructor

logger = logging.getLogger(__name__)

def make_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
    ip_min, ip_max = sorted([src_ip or "", dst_ip or ""])
    p_min, p_max = sorted([src_port or 0, dst_port or 0])
    return f"{ip_min}_{ip_max}_{p_min}_{p_max}_{protocol}"

class FlowEngine:
    def __init__(self):
        # Active sessions in memory: flow_key -> session_dict
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        # Buffer for batch persistence
        self.session_buffer: Dict[str, Dict[str, Any]] = {}
        self.payload_buffer: List[Tuple[Any, ...]] = []
        self.packet_buffer: List[Tuple[Any, ...]] = []
        
        self.running = False
        self._flush_task = None
        self.lock = asyncio.Lock()
        self.storage_failed = False

    def start(self):
        self.running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("FlowEngine batch flush loop started")

    async def stop(self):
        self.running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Perform one last flush of remaining items
        await self.flush_batch()

    def process_packet(self, parsed_pkt: dict) -> str:
        """
        Tracks the TCP/UDP/ICMP flow of the incoming packet.
        Updates state and appends to batch buffer.
        """
        src_ip = parsed_pkt.get("source_ip") or "0.0.0.0"
        dst_ip = parsed_pkt.get("destination_ip") or "0.0.0.0"
        src_port = parsed_pkt.get("source_port") or 0
        dst_port = parsed_pkt.get("destination_port") or 0
        protocol = parsed_pkt.get("protocol", "IP")
        length = parsed_pkt.get("length", 0)
        timestamp = parsed_pkt.get("timestamp", time.time())
        tcp_flags = parsed_pkt.get("tcp_flags", "")

        flow_key = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        
        # 1. Update/Create Session
        is_new = False
        if flow_key not in self.active_sessions:
            is_new = True
            self.active_sessions[flow_key] = {
                "flow_id": flow_key,
                "investigation_id": "live_capture",
                "protocol": protocol,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "start_time": timestamp,
                "end_time": timestamp,
                "bytes": length,
                "packets": 1,
                "c2s_bytes": length if src_ip < dst_ip else 0,
                "s2c_bytes": length if src_ip >= dst_ip else 0,
                "c2s_packets": 1 if src_ip < dst_ip else 0,
                "s2c_packets": 1 if src_ip >= dst_ip else 0,
                "rtt_ms": 0.0,
                "entropy": 0.0,
                "syn_timestamp": timestamp if (tcp_flags and "S" in tcp_flags.upper() and "A" not in tcp_flags.upper()) else None,
                "jitter": 0.0,
                "loss": 0.0,
                "mos": None,  # Computed from jitter/loss when session closes; None until then
                "classification": "Active Flow",
                "tcp_state": "INIT",
                "ja3_client": None,
                "ja3_server": None,
                "ja4_client": None,
                "ja4_server": None,
                "hassh": None,
                "hassh_server": None,
                "quic_sni": None,
                "quic_version": None
            }
        else:
            session = self.active_sessions[flow_key]
            session["end_time"] = timestamp
            session["bytes"] += length
            session["packets"] += 1
            if src_ip < dst_ip:
                session["c2s_bytes"] += length
                session["c2s_packets"] += 1
            else:
                session["s2c_bytes"] += length
                session["s2c_packets"] += 1
            
        session = self.active_sessions[flow_key]
        
        # 2. Track TCP Handshake State Machine & RTT
        if protocol == "TCP" and tcp_flags:
            flags = tcp_flags.upper()
            state = session.get("tcp_state", "INIT")
            
            if "S" in flags and "A" not in flags:  # SYN
                state = "SYN_SENT"
                session["syn_timestamp"] = timestamp
            elif "S" in flags and "A" in flags:  # SYN-ACK
                state = "SYN_RECEIVED"
                if session.get("syn_timestamp"):
                    rtt = (timestamp - session["syn_timestamp"]) * 1000.0
                    session["rtt_ms"] = round(rtt, 2)
            elif "F" in flags:  # FIN
                state = "FIN_WAIT"
            elif "R" in flags:  # RST
                state = "CLOSED"
            elif "A" in flags:  # ACK
                if state in ("SYN_SENT", "SYN_RECEIVED"):
                    state = "ESTABLISHED"
                    
            session["tcp_state"] = state
            session["classification"] = f"TCP {state}"

        # 3. Process payload details, stream reassembly, & fingerprinting
        raw_bytes = parsed_pkt.get("raw_bytes") or b""
        if raw_bytes:
            session["entropy"] = round(calculate_entropy(raw_bytes), 2)
            
            # Stream Reassembly Integration
            if protocol == "TCP":
                seq_num = parsed_pkt.get("seq_number")  # None if absent — do not default to 0 (corrupts reassembly)
                is_c2s = (src_ip < dst_ip)  # Deterministic lexicographic heuristic; not semantic direction
                if seq_num is not None:
                    reassembled = stream_reassembler.process_segment(flow_key, is_c2s, seq_num, raw_bytes)
                    target_payload = reassembled if reassembled else raw_bytes
                else:
                    target_payload = raw_bytes  # Skip reassembly if seq number unavailable
            elif protocol == "UDP":
                target_payload = udp_reconstructor.process_datagram(flow_key, raw_bytes)
            else:
                target_payload = raw_bytes

            # TLS Fingerprinting
            if protocol == "TCP":
                fps = get_tls_fingerprints(target_payload)
                if fps:
                    for k, v in fps.items():
                        if k == "ja3":
                            session["ja3_client"] = v
                            session["classification"] = f"TLS Client (JA3: {v[:8]})"
                        elif k == "ja3s":
                            session["ja3_server"] = v
                        elif k == "ja4":
                            session["ja4_client"] = v
                        elif k == "ja4s":
                            session["ja4_server"] = v

                # SSH HASSH Fingerprinting
                ssh_fps = parse_ssh_hassh(target_payload)
                if ssh_fps:
                    session["hassh"] = ssh_fps.get("hassh")
                    session["hassh_server"] = ssh_fps.get("hassh_server")
                    session["classification"] = f"SSH (HASSH: {ssh_fps.get('hassh', '')[:8]})"

            # QUIC Decoding
            elif protocol == "UDP" and (src_port == 443 or dst_port == 443):
                from app.protocols.quic import parse_quic_packet
                quic_info = parse_quic_packet(raw_bytes)
                if quic_info:
                    session["quic_sni"] = quic_info.get("sni")
                    session["quic_version"] = quic_info.get("version_name")
                    session["classification"] = f"QUIC {quic_info.get('version_name', '')}"
                
        # Buffer session metadata for persistence
        self.session_buffer[flow_key] = session.copy()
        
        # 4. Process payload persistence
        payload_preview = parsed_pkt.get("payload_preview") or ""
        payload_kind = parsed_pkt.get("payload_kind") or "plaintext"
        decoded_fields = parsed_pkt.get("decoded_fields") or {}
        
        # Compress and calculate entropy
        compressed = compress_bytes(raw_bytes)
        entropy = calculate_entropy(raw_bytes)
        src_id = get_endpoint_id(src_ip, parsed_pkt.get("source_mac"))
        dst_id = get_endpoint_id(dst_ip, parsed_pkt.get("destination_mac"))
        
        # For batching, we will insert packets, then payloads
        self.packet_buffer.append((
            "live_capture",
            session["packets"],  # packet index
            datetime_iso(timestamp),
            length,
            protocol,
            src_id,
            dst_id,
            src_port,
            dst_port,
            tcp_flags,
            flow_key,
            parsed_pkt.get("summary", f"{protocol} Packet")
        ))
        
        self.payload_buffer.append((
            "live_capture",
            session["packets"],
            compressed,
            payload_preview,
            payload_kind,
            json.dumps(decoded_fields),
            "zlib",
            entropy
        ))

        # 5. Broadcast standard record to WebSockets (Priority 3)
        # process_packet runs on the sniffer thread; use call_soon_threadsafe to schedule
        # coroutines from the async event loop safely.
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(
                loop.create_task,
                broadcast_manager.broadcast({
                    "type": "packet",
                    "flow_id": flow_key,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": src_port,
                    "destination_port": dst_port,
                    "protocol": protocol,
                    "length": length,
                    "timestamp": timestamp,
                    "summary": parsed_pkt.get("summary", ""),
                    "tcp_flags": tcp_flags,
                    "payload_preview": payload_preview,
                    "tcp_state": session.get("tcp_state", "")
                }, priority=3)
            )
        except RuntimeError:
            pass  # No running event loop (called from sync context) — skip broadcast
        
        return flow_key

    async def _flush_loop(self):
        while self.running:
            try:
                await asyncio.sleep(2.0)
                await self.flush_batch()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in FlowEngine flush loop: {e}", exc_info=True)

    async def flush_batch(self):
        """Executes executemany batch inserts for buffered flows, packets, and payloads."""
        async with self.lock:
            if not self.session_buffer and not self.packet_buffer:
                return

            sessions_to_write = list(self.session_buffer.values())
            packets_to_write = list(self.packet_buffer)
            payloads_to_write = list(self.payload_buffer)
            
            self.session_buffer.clear()
            self.packet_buffer.clear()
            self.payload_buffer.clear()
            
            # Write to SQLite via DatabaseRouter executemany
            max_retries = 3
            backoff_base = 0.5
            success = False
            error_msg = ""
            
            for attempt in range(max_retries):
                try:
                    # 1. Write Sessions to flows.sqlite3 ('sessions' table)
                    if sessions_to_write:
                        router.executemany(
                            "sessions",
                            """INSERT OR REPLACE INTO sessions 
                            (flow_id, investigation_id, protocol, start_time, end_time, bytes, packets, jitter, loss, mos, classification, ja3_client, ja3_server, ja4_client, ja4_server)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            [
                                (
                                    s["flow_id"], s["investigation_id"], s["protocol"], 
                                    datetime_iso(s["start_time"]), datetime_iso(s["end_time"]), 
                                    s["bytes"], s["packets"], s["jitter"], s["loss"], s["mos"], s["classification"],
                                    s.get("ja3_client"), s.get("ja3_server"), s.get("ja4_client"), s.get("ja4_server")
                                )
                                for s in sessions_to_write
                            ]
                        )

                    # 2. Write Packets to packets.sqlite3 with exact packet_id tracking
                    if packets_to_write:
                        db_path = router.table_map["packets"]
                        inserted_packet_ids = []
                        with router._get_connection(db_path) as conn:
                            for row in packets_to_write:
                                cur = conn.execute(
                                    """INSERT INTO packets 
                                    (investigation_id, packet_index, timestamp, length, protocol, src_endpoint_id, dst_endpoint_id, source_port, destination_port, tcp_flags, flow_id, summary) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
                                    row
                                )
                                inserted_packet_ids.append(cur.fetchone()[0])
                            conn.commit()

                        # 3. Write Payloads to payloads.sqlite3 linked strictly to confirmed packet_ids
                        if payloads_to_write:
                            if len(inserted_packet_ids) == len(payloads_to_write):
                                payload_rows_linked = [
                                    (inserted_packet_ids[i], *pl)
                                    for i, pl in enumerate(payloads_to_write)
                                ]
                                router.executemany(
                                    "payloads",
                                    """INSERT INTO payloads 
                                    (packet_id, investigation_id, packet_index, payload_blob, payload_preview, mime_type, decoded_json, compression, entropy) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                    payload_rows_linked
                                )
                            else:
                                logger.error(f"Flow batch insertion mismatch: {len(inserted_packet_ids)} packets vs {len(payloads_to_write)} payloads. Payloads omitted to prevent orphan FK records.")
                    success = True
                    break
                except sqlite3.OperationalError as e:
                    error_msg = str(e)
                    logger.warning(f"Database write attempt {attempt + 1} failed: {e}. Retrying in {backoff_base * (2 ** attempt)}s...")
                    await asyncio.sleep(backoff_base * (2 ** attempt))
                    
            if not success:
                # Disk Full or I/O failure handling after retries are exhausted
                self.storage_failed = True
                logger.critical(f"Disk I/O failure during flow batch insert after {max_retries} attempts: {error_msg}")
                # Notify clients via WebSocket (Priority 0)
                asyncio.create_task(broadcast_manager.broadcast({
                    "type": "alert",
                    "alert": {
                        "rule_name": "SQLite Write Stall",
                        "severity": "critical",
                        "category": "Storage",
                        "description": f"SQLite write queue stalled after {max_retries} retries. Live stream active but persistence paused. Details: {error_msg}",
                        "timestamp": time.time()
                    }
                }, priority=0))
            else:
                # Reset storage failure state if we succeed
                if self.storage_failed:
                    self.storage_failed = False
                    logger.info("SQLite persistence recovered successfully")

def datetime_iso(ts: float) -> str:
    """Convert a Unix timestamp to an ISO-8601 UTC string."""
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()

# Singleton
flow_engine = FlowEngine()
