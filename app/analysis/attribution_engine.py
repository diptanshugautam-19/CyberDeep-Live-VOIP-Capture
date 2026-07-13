from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set, Tuple
import struct
import ipaddress
import re
import sys

# NAT and attribution confidence definitions
AttributionConfidence = Literal["direct", "relay_only", "unresolved"]
NatTypeGuess = Literal["unknown", "symmetric", "full_cone", "restricted", "port_restricted"]
IceState = Literal["NEW", "GATHERING", "CHECKING", "CONNECTED", "COMPLETED", "FAILED", "RELAYED"]


class IpClassification(Enum):
    LOCAL_PRIVATE = "Local Private Endpoint"
    LOCAL_PUBLIC_NAT = "Local Public NAT Address"
    STUN_SERVER = "STUN Server"
    TURN_RELAY = "TURN Relay"
    SIGNALING_SERVER = "Signaling Server"
    DNS_RESOLVER = "DNS Resolver"
    PROVIDER_INFRASTRUCTURE = "Provider Infrastructure"
    REMOTE_PARTICIPANT = "Remote Participant"
    UNKNOWN = "Unknown"


@dataclass
class IceCandidate:
    candidate_type: str
    foundation: str
    component: int
    transport: str
    priority: int
    ip: str
    port: int
    generation: int = 0
    is_private: bool = False
    is_relay: bool = False


@dataclass
class RtpStream:
    ssrc: int
    ssrc_hex: str
    payload_type: int
    first_packet: int = 999999999
    last_packet: int = 0
    source_ips: Set[str] = field(default_factory=set)
    dest_ips: Set[str] = field(default_factory=set)
    is_srtp: bool = False
    packets_from: List[Tuple[str, int, int, float]] = field(default_factory=list)  # (src_ip, src_port, pkt_num, timestamp)
    packets_to: List[Tuple[str, int, int, float]] = field(default_factory=list)    # (dst_ip, dst_port, pkt_num, timestamp)

    def remote_source_ips(self, local_ips: Set[str]) -> Set[str]:
        """IPs that sent RTP but are not local."""
        return {p[0] for p in self.packets_from if p[0] not in local_ips}

    def remote_dest_ips(self, local_ips: Set[str]) -> Set[str]:
        """IPs that received RTP but are not local."""
        return {p[0] for p in self.packets_to if p[0] not in local_ips}


@dataclass
class EvidenceTrail:
    protocol: str
    packet_numbers: str
    ssrc: str
    candidate_type: str
    confidence: int
    reason: str
    evidence_source: str


@dataclass
class CallSummary:
    private_ip: Optional[str]
    public_nat: Optional[str]
    media_path: str
    relay_ip: Optional[str] = None
    provider: Optional[str] = None
    remote_ip: Optional[str] = None
    confidence: int = 0
    reason: str = ""
    stream_summaries: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class StreamAttribution:
    ssrc: int
    ssrc_hex: str
    stream_type: str
    is_relay: bool = False
    media_path: str = "Unknown"
    relay_ip: Optional[str] = None
    remote_ip: Optional[str] = None
    confidence: int = 0
    candidate: Optional[IceCandidate] = None
    evidence: Optional[EvidenceTrail] = None
    remote_observable: bool = False


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local:
            return True
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        return any(addr in net for net in private_networks)
    except Exception:
        return True


def _is_valid_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified:
            return False
        if ip.endswith(".255"):
            return False
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        return any(addr in net for net in private_networks)
    except Exception:
        return False


class StunFamilyMessage:
    def __init__(self, raw: bytes, src_ip: str, src_port: int, dst_ip: str, dst_port: int, timestamp: float):
        self.raw = raw
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.timestamp = timestamp
        
        self.is_valid = False
        self.method = ""
        self.msg_class = ""
        self.transaction_id = b""
        self.username = None
        self.remote_ufrag = None
        self.local_ufrag = None
        self.xor_mapped_address = None
        self.mapped_address = None
        self.xor_relayed_address = None
        self.xor_peer_address = None
        self.use_candidate = False
        
        if raw:
            self._parse()

    def _parse(self):
        if len(self.raw) < 20:
            return
        
        magic_cookie = struct.unpack_from(">I", self.raw, 4)[0]
        if magic_cookie != 0x2112A442:
            return
        if self.raw[0] & 0xC0:
            return
            
        self.is_valid = True
        msg_type = struct.unpack_from(">H", self.raw, 0)[0]
        msg_len = struct.unpack_from(">H", self.raw, 2)[0]
        self.transaction_id = self.raw[8:20]
        
        # Message class parsing
        c1 = (msg_type & 0x0100) >> 7
        c0 = (msg_type & 0x0010) >> 4
        c_val = c1 | c0
        classes = {0: "Request", 1: "Indication", 2: "Success Response", 3: "Error Response"}
        self.msg_class = classes.get(c_val, "Unknown")
        
        # Message method parsing
        method_val = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2)
        methods = {
            1: "Binding",
            3: "Allocate",
            4: "Refresh",
            6: "Send",
            7: "Data",
            9: "CreatePermission",
            10: "ChannelBind"
        }
        self.method = methods.get(method_val, f"Method-{method_val}")
        
        # Parse attributes
        offset = 20
        end = 20 + msg_len
        if end > len(self.raw):
            return
            
        try:
            while offset + 4 <= end:
                attr_type = struct.unpack_from(">H", self.raw, offset)[0]
                attr_len = struct.unpack_from(">H", self.raw, offset + 2)[0]
                if offset + 4 + attr_len > end:
                    break
                    
                val = self.raw[offset + 4 : offset + 4 + attr_len]
                
                # Attribute mapping
                if attr_type == 0x0006:  # USERNAME
                    self.username = bytes(val).decode("utf-8", errors="replace")
                    if ":" in self.username:
                        parts = self.username.split(":", 1)
                        self.remote_ufrag = parts[0]
                        self.local_ufrag = parts[1]
                    else:
                        self.remote_ufrag = self.username
                elif attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                    self.xor_mapped_address = self._decode_xor(val)
                elif attr_type == 0x0001:  # MAPPED-ADDRESS
                    self.mapped_address = self._decode_mapped(val)
                elif attr_type == 0x0016:  # XOR-RELAYED-ADDRESS
                    self.xor_relayed_address = self._decode_xor(val)
                elif attr_type == 0x0012:  # XOR-PEER-ADDRESS
                    self.xor_peer_address = self._decode_xor(val)
                elif attr_type == 0x0025:  # USE-CANDIDATE
                    self.use_candidate = True
                    
                offset += 4 + ((attr_len + 3) & ~3)
        except Exception:
            pass

    def _decode_xor(self, val: bytes) -> Optional[Tuple[str, int]]:
        if len(val) < 4:
            return None
        family = struct.unpack_from(">H", val, 1)[0]
        xor_port = struct.unpack_from(">H", val, 3)[0]
        port = xor_port ^ (0x2112A442 >> 16)
        if family == 1:  # IPv4
            if len(val) < 8:
                return None
            xor_addr = struct.unpack_from(">I", val, 4)[0]
            addr = xor_addr ^ 0x2112A442
            ip = ".".join(str((addr >> (24 - 8*i)) & 0xFF) for i in range(4))
            return ip, port
        elif family == 2:  # IPv6
            if len(val) < 20:
                return None
            xor_addr = val[4:20]
            xor_mask = struct.pack(">I", 0x2112A442) + self.transaction_id
            addr_bytes = bytes(a ^ b for a, b in zip(xor_addr, xor_mask))
            ip = str(ipaddress.ip_address(addr_bytes))
            return ip, port
        return None

    def _decode_mapped(self, val: bytes) -> Optional[Tuple[str, int]]:
        if len(val) < 4:
            return None
        family = struct.unpack_from(">H", val, 1)[0]
        port = struct.unpack_from(">H", val, 3)[0]
        if family == 1:  # IPv4
            if len(val) < 8:
                return None
            ip = ".".join(str(b) for b in val[4:8])
            return ip, port
        elif family == 2:  # IPv6
            if len(val) < 20:
                return None
            ip = str(ipaddress.ip_address(val[4:20]))
            return ip, port
        return None


class SdpParser:
    def __init__(self):
        self.candidates: List[IceCandidate] = []
        self.ice_ufrag: Optional[str] = None
        self.ice_pwd: Optional[str] = None
        self.sdp_media_ip: Optional[str] = None
        self.media_ports: Dict[str, List[int]] = {"audio": [], "video": []}

    def parse_sdp(self, sdp_string: str):
        for line in sdp_string.splitlines():
            line = line.strip()
            if line.startswith("a=candidate:"):
                self._parse_candidate(line[12:])
            elif line.startswith("a=ice-ufrag:"):
                self.ice_ufrag = line[12:].strip()
            elif line.startswith("a=ice-pwd:"):
                self.ice_pwd = line[10:].strip()
            elif line.startswith("c=IN IP4 ") or line.startswith("c=IN IP6 "):
                self.sdp_media_ip = line.split()[-1].strip()
            elif line.startswith("m=audio "):
                try:
                    port = int(line.split()[1])
                    self.media_ports["audio"].append(port)
                except (IndexError, ValueError):
                    pass
            elif line.startswith("m=video "):
                try:
                    port = int(line.split()[1])
                    self.media_ports["video"].append(port)
                except (IndexError, ValueError):
                    pass

    def _parse_candidate(self, body: str) -> None:
        f = body.split()
        if len(f) < 8 or f[6] != "typ":  # Malformed candidate line or missing 'typ' keyword
            return
        
        ip = f[4]
        candidate_type = f[7]
        is_private = _is_private_ip(ip)
        is_relay = (candidate_type == "relay")
        
        cand = IceCandidate(
            candidate_type=candidate_type,
            foundation=f[0],
            component=int(f[1]),
            transport=f[2],
            priority=int(f[3]),
            ip=ip,
            port=int(f[5]),
            generation=0,
            is_private=is_private,
            is_relay=is_relay
        )
        
        # Parse optional attributes
        i = 8
        while i < len(f) - 1:
            if f[i] == "generation":
                try:
                    cand.generation = int(f[i+1])
                except ValueError:
                    pass
                i += 2
            elif f[i] == "raddr":
                i += 2
            elif f[i] == "rport":
                i += 2
            else:
                i += 1
        self.candidates.append(cand)


class RtpParser:
    def __init__(self):
        self.streams: Dict[int, RtpStream] = {}
        self.packet_count = 0

    def parse_packet(self, raw: bytes, src_ip: str, src_port: int, dst_ip: str, dst_port: int, timestamp: float, local_ips: Set[str]):
        if len(raw) < 12:
            return
        v_p_x_cc = raw[0]
        version = (v_p_x_cc & 0xC0) >> 6
        if version != 2:
            return
            
        m_pt = raw[1]
        payload_type = m_pt & 0x7F
        
        # Standard dynamic range dynamic protocols check
        if not ((0 <= payload_type <= 34) or (96 <= payload_type <= 127)):
            return
            
        seq_num = struct.unpack(">H", raw[2:4])[0]
        ssrc = struct.unpack(">I", raw[8:12])[0]
        
        is_srtp = True  # WebRTC defaults to SRTP
        
        if ssrc not in self.streams:
            self.streams[ssrc] = RtpStream(
                ssrc=ssrc,
                ssrc_hex=f"0x{ssrc:08X}",
                payload_type=payload_type,
                is_srtp=is_srtp
            )
            
        stream = self.streams[ssrc]
        self.packet_count += 1
        pkt_num = self.packet_count
        
        stream.first_packet = min(stream.first_packet, pkt_num)
        stream.last_packet = max(stream.last_packet, pkt_num)
        stream.source_ips.add(src_ip)
        stream.dest_ips.add(dst_ip)
        
        stream.packets_from.append((src_ip, src_port, pkt_num, timestamp))
        stream.packets_to.append((dst_ip, dst_port, pkt_num, timestamp))

    def get_all_streams(self) -> List[RtpStream]:
        return list(self.streams.values())


class QuicDetector:
    def __init__(self):
        self.quic_endpoints: Set[Tuple[str, int]] = set()

    def process_packet(self, raw: bytes, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        is_quic = (src_port == 443 or dst_port == 443)
        if not is_quic or not raw or len(raw) < 5:
            return
            
        first_byte = raw[0]
        is_long_header = bool(first_byte & 0x80)
        is_short_header = ((first_byte & 0xC0) == 0x40)
        
        if is_long_header or is_short_header:
            self.quic_endpoints.add((src_ip, src_port))
            self.quic_endpoints.add((dst_ip, dst_port))


class CorrelationEngine:
    def __init__(self):
        self.ice_state: IceState = "NEW"
        self.ufrag_pairs: Set[Tuple[str, str]] = set()
        self.transaction_to_ufrag: Dict[str, str] = {}
        self.stun_servers: Set[str] = set()
        self.turn_relays: Set[str] = set()
        self.signaling_servers: Set[str] = set()
        self.nat_mappings: Dict[str, Tuple[str, int]] = {}
        self.selected_pairs: List[Tuple[str, str]] = []

    def ingest_stun(self, msg: StunFamilyMessage):
        if msg.remote_ufrag and msg.local_ufrag:
            self.ufrag_pairs.add((msg.remote_ufrag, msg.local_ufrag))
            self.transaction_to_ufrag[msg.transaction_id.hex()] = msg.remote_ufrag
            
        if self.ice_state == "NEW":
            self.ice_state = "GATHERING"
            
        if msg.method == "Binding":
            if msg.msg_class == "Request":
                if self.ice_state == "GATHERING":
                    self.ice_state = "CHECKING"
            elif msg.msg_class == "Success Response":
                if msg.xor_mapped_address:
                    self.nat_mappings[msg.dst_ip] = msg.xor_mapped_address
                    
                if msg.use_candidate:
                    self.ice_state = "CONNECTED"
                    self.selected_pairs.append((msg.dst_ip, msg.src_ip))
                    
        elif msg.method == "Allocate":
            if msg.msg_class == "Success Response" and msg.xor_relayed_address:
                self.turn_relays.add(msg.xor_relayed_address[0])
                self.turn_relays.add(msg.src_ip)
                self.ice_state = "RELAYED"

        if msg.src_port in {3478, 3479, 5349, 19302, 19305}:
            self.stun_servers.add(msg.src_ip)
        if msg.dst_port in {3478, 3479, 5349, 19302, 19305}:
            self.stun_servers.add(msg.dst_ip)

    def matches_ufrag(self, ufrag: str) -> bool:
        if not ufrag:
            return False
        for remote, local in self.ufrag_pairs:
            if ufrag == remote or ufrag == local:
                return True
        for rem in self.transaction_to_ufrag.values():
            if ufrag == rem:
                return True
        return False

    def get_turn_relays(self) -> Set[str]:
        return self.turn_relays

    def finalize_ice_state(self) -> None:
        if self.ice_state == "CONNECTED":
            if self.selected_pairs:
                self.ice_state = "COMPLETED"
        elif self.ice_state == "CHECKING":
            self.ice_state = "FAILED"


class InfraClassifier:
    def __init__(self, correlation_engine: CorrelationEngine):
        self.correlation = correlation_engine
        self._cache: Dict[str, IpClassification] = {}
        
    def classify(self, ip: str) -> IpClassification:
        if ip in self._cache:
            return self._cache[ip]
        res = self._classify_uncached(ip)
        self._cache[ip] = res
        return res

    def _classify_uncached(self, ip: str) -> IpClassification:
        if _is_private_ip(ip):
            return IpClassification.LOCAL_PRIVATE
            
        for local_ip, (public_ip, _) in self.correlation.nat_mappings.items():
            if ip == public_ip:
                return IpClassification.LOCAL_PUBLIC_NAT
                
        if ip in self.correlation.stun_servers:
            return IpClassification.STUN_SERVER
            
        if ip in self.correlation.turn_relays:
            return IpClassification.TURN_RELAY
            
        from app.enrichment.telecom import enrich_telecom
        enrich = enrich_telecom(ip)
        org = enrich.get("asn_org", "").lower()
        if any(prov in org for prov in ["meta", "facebook", "google", "microsoft", "azure", "cloudflare", "amazon", "aws"]):
            return IpClassification.PROVIDER_INFRASTRUCTURE
            
        if ip in self.correlation.signaling_servers:
            return IpClassification.SIGNALING_SERVER
            
        return IpClassification.REMOTE_PARTICIPANT


class AttributionEngine:
    def __init__(self):
        self.sdp_parser = SdpParser()
        self.correlation = CorrelationEngine()
        self.rtp_parser = RtpParser()
        self.quic_detector = QuicDetector()
        self.infra_classifier = InfraClassifier(self.correlation)
        
        self.local_ips: Set[str] = set()
        self.packet_count = 0
        self._provider_detected: Optional[str] = None
        self._stream_attributions: Dict[int, StreamAttribution] = {}

    def ingest_sdp(self, sdp_string: str):
        self.sdp_parser.parse_sdp(sdp_string)
        if self.sdp_parser.sdp_media_ip:
            self.local_ips.add(self.sdp_parser.sdp_media_ip)
        for cand in self.sdp_parser.candidates:
            if cand.candidate_type == "host":
                self.local_ips.add(cand.ip)

    def ingest_packet(self, packet_bytes: bytes, src_ip: str, src_port: int, dst_ip: str, dst_port: int, timestamp: float):
        self.packet_count += 1
        
        # 1. Process SIP/SDP
        if src_port == 5060 or dst_port == 5060 or packet_bytes.startswith(b"INVITE") or packet_bytes.startswith(b"SIP/2.0"):
            self.correlation.signaling_servers.add(src_ip)
            self.correlation.signaling_servers.add(dst_ip)
            try:
                from app.protocols.sip import parse_sip_message
                msg = parse_sip_message(packet_bytes)
                if msg:
                    sdp_str = packet_bytes.decode("utf-8", errors="replace")
                    self.ingest_sdp(sdp_str)
            except Exception:
                pass
            return

        # 2. Process STUN family
        stun_msg = StunFamilyMessage(packet_bytes, src_ip, src_port, dst_ip, dst_port, timestamp)
        if stun_msg.is_valid:
            self.correlation.ingest_stun(stun_msg)
            return

        # 3. Process QUIC
        self.quic_detector.process_packet(packet_bytes, src_ip, src_port, dst_ip, dst_port)
        if src_port == 443 or dst_port == 443:
            provider_ip = src_ip if src_port == 443 else dst_ip
            from app.enrichment.telecom import enrich_telecom
            enrich = enrich_telecom(provider_ip)
            org = enrich.get("asn_org", "").lower()
            for prov in ["meta", "facebook", "google", "microsoft", "cloudflare"]:
                if prov in org:
                    self._provider_detected = "Meta" if prov in ("meta", "facebook") else prov.capitalize()
                    break

        # 4. Process RTP
        self.rtp_parser.parse_packet(packet_bytes, src_ip, src_port, dst_ip, dst_port, timestamp, self.local_ips)

    def ingest_parsed_logs(self, stun_packets: list[dict], rtp_packets: list[dict], sip_messages: list[dict]):
        for msg in sip_messages:
            sdp_candidates = msg.get("sdp_candidates") or []
            for c in sdp_candidates:
                cand = IceCandidate(
                    candidate_type=c.get("candidate_type", "host"),
                    foundation=c.get("foundation", "1"),
                    component=c.get("component_id", 1),
                    transport=c.get("transport", "udp"),
                    priority=c.get("priority", 0),
                    ip=c.get("ip"),
                    port=c.get("port"),
                    is_private=_is_private_ip(c.get("ip")),
                    is_relay=(c.get("candidate_type") == "relay")
                )
                self.sdp_parser.candidates.append(cand)
                
            if msg.get("sdp_media_ip"):
                self.local_ips.add(msg["sdp_media_ip"])
                
        for p in stun_packets:
            msg = StunFamilyMessage(b"", p.get("source_ip"), p.get("source_port", 0), p.get("destination_ip"), p.get("destination_port", 0), p.get("timestamp", 0))
            msg.is_valid = True
            mname = p.get("message_name", "")
            msg.method = mname.split()[0] if " " in mname else mname
            if "Success Response" in mname:
                msg.msg_class = "Success Response"
            elif "Error Response" in mname:
                msg.msg_class = "Error Response"
            elif "Request" in mname:
                msg.msg_class = "Request"
            else:
                msg.msg_class = "Indication"
                
            msg.remote_ufrag = p.get("remote_ufrag")
            msg.local_ufrag = p.get("local_ufrag")
            msg.transaction_id = bytes.fromhex(p.get("transaction_id", "")) if p.get("transaction_id") else b""
            
            if p.get("xor_mapped_address"):
                msg.xor_mapped_address = (p["xor_mapped_address"]["ip"], p["xor_mapped_address"]["port"])
            if p.get("mapped_address"):
                msg.mapped_address = (p["mapped_address"]["ip"], p["mapped_address"]["port"])
            if p.get("xor_relayed_address"):
                msg.xor_relayed_address = (p["xor_relayed_address"]["ip"], p["xor_relayed_address"]["port"])
            if p.get("xor_peer_address"):
                msg.xor_peer_address = (p["xor_peer_address"]["ip"], p["xor_peer_address"]["port"])
            if p.get("use_candidate"):
                msg.use_candidate = True
                
            self.correlation.ingest_stun(msg)

        for i, p in enumerate(rtp_packets):
            ssrc = p.get("ssrc")
            if ssrc:
                if ssrc not in self.rtp_parser.streams:
                    self.rtp_parser.streams[ssrc] = RtpStream(
                        ssrc=ssrc,
                        ssrc_hex=f"0x{ssrc:08X}",
                        payload_type=p.get("payload_type", 0),
                        is_srtp=True
                    )
                stream = self.rtp_parser.streams[ssrc]
                pkt_num = i + 1
                stream.first_packet = min(stream.first_packet, pkt_num)
                stream.last_packet = max(stream.last_packet, pkt_num)
                src_ip = p.get("source_ip")
                dst_ip = p.get("destination_ip")
                stream.source_ips.add(src_ip)
                stream.dest_ips.add(dst_ip)
                stream.packets_from.append((src_ip, p.get("source_port", 0), pkt_num, p.get("timestamp", 0)))
                stream.packets_to.append((dst_ip, p.get("destination_port", 0), pkt_num, p.get("timestamp", 0)))

    def _attribute_stream(self, stream: RtpStream) -> StreamAttribution:
        attr = StreamAttribution(
            ssrc=stream.ssrc,
            ssrc_hex=stream.ssrc_hex,
            stream_type=self._classify_stream_type(stream)
        )
        
        turn_relays = self.correlation.get_turn_relays()
        all_stream_ips = stream.source_ips | stream.dest_ips
        
        is_relayed = False
        relay_ip = None
        for ip in all_stream_ips:
            if ip in turn_relays or self.infra_classifier.classify(ip) == IpClassification.TURN_RELAY:
                is_relayed = True
                relay_ip = ip
                break
                
        if is_relayed:
            attr.is_relay = True
            attr.media_path = "TURN Relay"
            attr.relay_ip = relay_ip
            attr.confidence = 0
            attr.remote_observable = False
            attr.evidence = EvidenceTrail(
                protocol="SRTP" if stream.is_srtp else "RTP",
                packet_numbers=f"{stream.first_packet}–{stream.last_packet}",
                ssrc=stream.ssrc_hex,
                candidate_type="relay",
                confidence=0,
                reason="RTP endpoint matches a known TURN relay.",
                evidence_source="RTP endpoint analysis"
            )
            return attr

        nat_ips = set()
        for local_ip, (public_ip, _) in self.correlation.nat_mappings.items():
            nat_ips.add(public_ip)
            
        remote_candidates = []
        for ip in stream.source_ips:
            if ip in nat_ips:
                continue
            cls = self.infra_classifier.classify(ip)
            if cls in (IpClassification.UNKNOWN, IpClassification.REMOTE_PARTICIPANT):
                if not _is_private_ip(ip):
                    remote_candidates.append(ip)
                    
        if not remote_candidates:
            for ip in stream.dest_ips:
                if ip in nat_ips:
                    continue
                cls = self.infra_classifier.classify(ip)
                if cls in (IpClassification.UNKNOWN, IpClassification.REMOTE_PARTICIPANT):
                    if not _is_private_ip(ip):
                        remote_candidates.append(ip)

        remote_candidates = list(set(remote_candidates))

        if len(remote_candidates) == 1:
            attr.remote_ip = remote_candidates[0]
            attr.confidence = 100
            attr.media_path = "Peer-to-Peer"
            attr.remote_observable = True
            
            matched_cand = self._find_ice_candidate_for_ip(attr.remote_ip)
            cand_type = matched_cand.candidate_type if matched_cand else "srflx"
            attr.candidate = matched_cand
            
            attr.evidence = EvidenceTrail(
                protocol="SRTP" if stream.is_srtp else "RTP",
                packet_numbers=f"{stream.first_packet}–{stream.last_packet}",
                ssrc=stream.ssrc_hex,
                candidate_type=cand_type,
                confidence=100,
                reason="Direct RTP endpoint after successful ICE negotiation.",
                evidence_source="RTP stream analysis"
            )
        elif len(remote_candidates) > 1:
            attr.confidence = 0
            attr.remote_observable = False
            attr.evidence = EvidenceTrail(
                protocol="SRTP" if stream.is_srtp else "RTP",
                packet_numbers=f"{stream.first_packet}–{stream.last_packet}",
                ssrc=stream.ssrc_hex,
                candidate_type="prflx",
                confidence=0,
                reason="Multiple candidate RTP endpoints; cannot uniquely attribute.",
                evidence_source="RTP stream analysis"
            )
        else:
            attr.confidence = 0
            attr.remote_observable = False
            attr.evidence = EvidenceTrail(
                protocol="SRTP" if stream.is_srtp else "RTP",
                packet_numbers=f"{stream.first_packet}–{stream.last_packet}",
                ssrc=stream.ssrc_hex,
                candidate_type="host",
                confidence=0,
                reason="No observable remote RTP endpoint.",
                evidence_source="RTP stream analysis"
            )
            
        return attr

    def _find_ice_candidate_for_ip(self, ip: str) -> Optional[IceCandidate]:
        for cand in self.sdp_parser.candidates:
            if cand.ip == ip:
                return cand
        return None

    _AUDIO_PT = {0, 8, 9, 3, 4, 5, 6, 7, 11, 12, 13, 15, 16, 17, 18, 19}
    _VIDEO_PT = {31, 32, 33, 34}
    
    def _classify_stream_type(self, stream: RtpStream) -> str:
        # Match observed ports against SDP parsed media ports
        stream_ports = set()
        for p in stream.packets_from:
            stream_ports.add(p[1])  # src_port
        for p in stream.packets_to:
            stream_ports.add(p[1])  # dst_port
            
        for port in stream_ports:
            if port in self.sdp_parser.media_ports["audio"]:
                return "Audio"
            if port in self.sdp_parser.media_ports["video"]:
                return "Video"

        # Fallback to static payload types
        if stream.payload_type in self._AUDIO_PT:
            return "Audio"
        if stream.payload_type in self._VIDEO_PT:
            return "Video"
        return "Unknown"

    def analyze(self) -> CallSummary:
        self.correlation.finalize_ice_state()
        
        summary = CallSummary(
            private_ip=next(iter(self.local_ips)) if self.local_ips else None,
            public_nat=None,
            media_path="Unknown",
            relay_ip=None,
            provider=None,
            remote_ip=None,
            confidence=0,
            reason="Insufficient protocol evidence to attribute remote participant IP.",
            stream_summaries=[]
        )

        if self.correlation.nat_mappings:
            first_nat = next(iter(self.correlation.nat_mappings.values()))
            summary.public_nat = first_nat[0]

        # ─── HIGHEST PRIORITY: QUIC Provider Infrastructure ───
        if self.quic_detector.quic_endpoints:
            all_rtp_ips = set()
            for stream in self.rtp_parser.get_all_streams():
                all_rtp_ips |= stream.source_ips | stream.dest_ips
            quic_ips = {ep[0] for ep in self.quic_detector.quic_endpoints}
            if not all_rtp_ips or all_rtp_ips.issubset(quic_ips):
                summary.media_path = "Provider Infrastructure"
                summary.provider = self._provider_detected or "Unknown"
                summary.remote_ip = None
                summary.confidence = 0
                summary.reason = (
                    "Media remained entirely within "
                    "provider-owned relay infrastructure."
                )
                self._build_stream_attributions_provider(self._provider_detected or "Unknown")
                self._aggregate_call_summary(summary)
                return summary

        # ─── SECOND HIGHEST: Relay check ───
        turn_relayed = False
        for pair in self.correlation.selected_pairs:
            if pair[1] in self.correlation.turn_relays:
                turn_relayed = True
                summary.relay_ip = pair[1]
                break
                
        if turn_relayed or self.correlation.ice_state == "RELAYED":
            summary.media_path = "TURN Relay"
            summary.remote_ip = None
            summary.confidence = 0
            summary.reason = "Selected relay ICE candidate."
            summary.relay_ip = summary.relay_ip or (next(iter(self.correlation.turn_relays)) if self.correlation.turn_relays else None)
            self._build_stream_attributions_relay(summary.relay_ip)
            self._aggregate_call_summary(summary)
            return summary

        # ─── Per-SSRC RTP Attribution Gate ───
        self._stream_attributions.clear()
        for stream in self.rtp_parser.get_all_streams():
            attr = self._attribute_stream(stream)
            self._stream_attributions[stream.ssrc] = attr

        for ssrc, attr in self._stream_attributions.items():
            if self._is_rtp_endpoint_relay(attr):
                attr.is_relay = True
                attr.remote_ip = None
                attr.confidence = 0

        self._aggregate_call_summary(summary)

        observable_streams = [
            a for a in self._stream_attributions.values()
            if a.remote_observable and not a.is_relay
        ]

        if not observable_streams:
            selected_remotes = []
            for pair in self.correlation.selected_pairs:
                remote_ip = pair[1]
                if not _is_private_ip(remote_ip) and remote_ip not in self.correlation.turn_relays:
                    selected_remotes.append(remote_ip)
                    
            if selected_remotes:
                summary.remote_ip = selected_remotes[0]
                summary.confidence = 90
                summary.media_path = "Peer-to-Peer"
                cand = self._find_ice_candidate_for_ip(summary.remote_ip)
                c_type = cand.candidate_type if cand else "srflx"
                summary.reason = f"Selected ICE candidate type={c_type}."
            else:
                sdp_public = [
                    c for c in self.sdp_parser.candidates
                    if not c.is_private and not c.is_relay
                ]
                if sdp_public:
                    summary.reason = "Candidate Only — Not Confirmed"
                    summary.confidence = 0
                else:
                    summary.reason = (
                        "Insufficient protocol evidence to attribute "
                        "remote participant IP."
                    )
                    summary.confidence = 0
                summary.remote_ip = None
        else:
            first = observable_streams[0]
            summary.remote_ip = first.remote_ip
            summary.confidence = first.confidence
            summary.media_path = "Peer-to-Peer"
            summary.reason = first.evidence.reason if first.evidence else ""

        return summary

    def _build_stream_attributions_provider(self, provider: str):
        self._stream_attributions.clear()
        for stream in self.rtp_parser.get_all_streams():
            attr = StreamAttribution(
                ssrc=stream.ssrc,
                ssrc_hex=stream.ssrc_hex,
                stream_type=self._classify_stream_type(stream),
                media_path="Provider Infrastructure",
                confidence=0,
                remote_observable=False,
                evidence=EvidenceTrail(
                    protocol="QUIC",
                    packet_numbers=f"{stream.first_packet}–{stream.last_packet}",
                    ssrc=stream.ssrc_hex,
                    candidate_type="relay",
                    confidence=0,
                    reason=f"Media remained entirely within provider-owned relay infrastructure ({provider}).",
                    evidence_source="QUIC stream analysis"
                )
            )
            self._stream_attributions[stream.ssrc] = attr

    def _build_stream_attributions_relay(self, relay_ip: Optional[str]):
        self._stream_attributions.clear()
        for stream in self.rtp_parser.get_all_streams():
            attr = StreamAttribution(
                ssrc=stream.ssrc,
                ssrc_hex=stream.ssrc_hex,
                stream_type=self._classify_stream_type(stream),
                is_relay=True,
                media_path="TURN Relay",
                relay_ip=relay_ip,
                confidence=0,
                remote_observable=False,
                evidence=EvidenceTrail(
                    protocol="SRTP" if stream.is_srtp else "RTP",
                    packet_numbers=f"{stream.first_packet}–{stream.last_packet}",
                    ssrc=stream.ssrc_hex,
                    candidate_type="relay",
                    confidence=0,
                    reason="Media is relayed through TURN server.",
                    evidence_source="RTP stream analysis"
                )
            )
            self._stream_attributions[stream.ssrc] = attr

    def _is_rtp_endpoint_relay(self, attr: StreamAttribution) -> bool:
        if attr.ssrc not in self.rtp_parser.streams:
            return False
        stream = self.rtp_parser.streams[attr.ssrc]
        all_ips = stream.source_ips | stream.dest_ips
        turn_relays = self.correlation.get_turn_relays()
        return bool(all_ips & turn_relays)

    def _aggregate_call_summary(self, summary: CallSummary) -> None:
        paths = set()
        for ssrc, attr in self._stream_attributions.items():
            stream_type = attr.stream_type
            if attr.is_relay:
                path = "TURN Relay"
            elif attr.remote_observable:
                path = "Direct"
            else:
                path = attr.media_path if attr.media_path != "Unknown" else "Unknown"
            paths.add(path)
            summary.stream_summaries.append({
                "type": stream_type,
                "ssrc": attr.ssrc_hex,
                "path": path,
            })

        if not paths:
            return

        if len(paths) == 1:
            summary.media_path = paths.pop()
        elif paths == {"Direct", "TURN Relay"}:
            summary.media_path = "Mixed Transport"
        elif "TURN Relay" in paths:
            summary.media_path = "TURN Relay"
        elif "Direct" in paths:
            summary.media_path = "Peer-to-Peer"
        elif "Provider Infrastructure" in paths:
            summary.media_path = "Provider Infrastructure"
        else:
            summary.media_path = "Unknown"

    def _get_first_evidence_protocol(self) -> Optional[str]:
        for attr in self._stream_attributions.values():
            if attr.evidence and attr.evidence.protocol:
                return attr.evidence.protocol
        return None


class OutputFormatter:
    @staticmethod
    def format(summary: CallSummary, engine: AttributionEngine) -> str:
        if summary.media_path == "TURN Relay":
            relay_str = summary.relay_ip if summary.relay_ip else "Not Observable"
            return (
                f"Private IP:\n{summary.private_ip or 'Not Observable'}\n\n"
                f"Public NAT:\n{summary.public_nat or 'Not Observable'}\n\n"
                f"Media:\nTURN Relay\n\n"
                f"Relay:\n{relay_str}\n\n"
                f"Remote Participant:\nNot Observable\n\n"
                f"Reason:\n{summary.reason}\n\n"
                f"Confidence:\n0%"
            )
            
        if summary.media_path == "Provider Infrastructure":
            return (
                f"Private IP:\n{summary.private_ip or 'Not Observable'}\n\n"
                f"Media:\nProvider Infrastructure\n\n"
                f"Provider:\n{summary.provider or 'Unknown'}\n\n"
                f"Remote Participant:\nNot Observable\n\n"
                f"Reason:\n{summary.reason}\n\n"
                f"Confidence:\n0%"
            )
            
        if summary.media_path == "Peer-to-Peer" and summary.remote_ip:
            return (
                f"Private IP:\n{summary.private_ip or 'Not Observable'}\n\n"
                f"Public NAT:\n{summary.public_nat or 'Not Observable'}\n\n"
                f"Media:\nPeer-to-Peer\n\n"
                f"Remote Participant:\n{summary.remote_ip}\n\n"
                f"Evidence:\n{engine._get_first_evidence_protocol() or 'RTP'}\n\n"
                f"Confidence:\n{summary.confidence}%"
            )
            
        return (
            f"Remote Participant Public IP:\nNot Observable"
        )

    @staticmethod
    def format_evidence(summary: CallSummary, engine: AttributionEngine) -> str:
        lines = []
        for ssrc, attr in engine._stream_attributions.items():
            if attr.evidence:
                lines.append(
                    f"Evidence\n\n"
                    f"Protocol:\n{attr.evidence.protocol}\n\n"
                    f"Packets:\n{attr.evidence.packet_numbers}\n\n"
                    f"SSRC:\n{attr.evidence.ssrc}\n\n"
                    f"Candidate:\n{attr.evidence.candidate_type or 'Unknown'}\n\n"
                    f"Confidence:\n{attr.evidence.confidence}%\n\n"
                    f"Reason:\n{attr.evidence.reason}"
                )
        return "\n---\n".join(lines)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Remote Participant Public IP Attribution Engine CLI")
    parser.add_argument("pcap_path", help="Path to PCAP/PCAPNG file to analyze")
    parser.add_argument("--sdp", help="Optional path to SDP file")
    args = parser.parse_args()
    
    engine = AttributionEngine()
    if args.sdp:
        with open(args.sdp, "r", encoding="utf-8") as f:
            engine.ingest_sdp(f.read())
            
    try:
        from scapy.all import rdpcap, IP, IPv6, UDP, TCP, Raw
        packets = rdpcap(args.pcap_path)
    except Exception as exc:
        print(f"Error loading scapy or PCAP file: {exc}")
        sys.exit(1)
        
    for i, pkt in enumerate(packets):
        src_ip = dst_ip = None
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            
        if not src_ip or not dst_ip:
            continue
            
        src_port = dst_port = None
        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            
        if not src_port or not dst_port:
            continue
            
        payload = bytes(pkt[Raw].load) if Raw in pkt else b""
        timestamp = float(pkt.time)
        
        engine.ingest_packet(payload, src_ip, src_port, dst_ip, dst_port, timestamp)
        
    summary = engine.analyze()
    print("=== ANALYSIS RESULTS ===")
    print(OutputFormatter.format(summary, engine))
    
    evidence = OutputFormatter.format_evidence(summary, engine)
    if evidence:
        print("\n=== EVIDENCE TRAIL ===")
        print(evidence)
