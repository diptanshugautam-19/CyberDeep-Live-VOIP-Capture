import re
import base64

class DPIRule:
    def __init__(self, name: str, category: str, severity: str, description: str):
        self.name = name
        self.category = category
        self.severity = severity
        self.description = description

    def match(self, packet: dict, raw_payload: bytes | None) -> dict | None:
        raise NotImplementedError

class RegexRule(DPIRule):
    def __init__(self, name: str, category: str, severity: str, description: str, pattern: str, search_hex: bool = False):
        super().__init__(name, category, severity, description)
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.search_hex = search_hex

    def match(self, packet: dict, raw_payload: bytes | None) -> dict | None:
        text = ""
        if self.search_hex and raw_payload:
            text = raw_payload.hex()
        else:
            # Check payload preview
            text = packet.get("payload_preview") or ""

        if not text:
            return None

        match_obj = self.regex.search(text)
        if match_obj:
            matched_text = match_obj.group(0)
            if len(matched_text) > 80:
                matched_text = matched_text[:77] + "..."
            return {
                "rule_name": self.name,
                "category": self.category,
                "severity": self.severity,
                "description": self.description,
                "matched_text": matched_text,
                "extracted_fields": {
                    "matched": match_obj.group(0)[:150]
                }
            }
        return None

# --- Structured Rules ---

class STUNStructuredRule(DPIRule):
    def __init__(self):
        super().__init__(
            name="STUN Binary Handshake",
            category="VoIP",
            severity="Info",
            description="Detected STUN protocol via 0x2112A442 magic cookie binary validation."
        )

    def match(self, packet: dict, raw_payload: bytes | None) -> dict | None:
        if not raw_payload or len(raw_payload) < 20:
            return None
        # Check Magic Cookie: 0x2112A442
        if raw_payload[4:8] == b"\x21\x12\xa4\x42":
            msg_type = int.from_bytes(raw_payload[:2], "big")
            msg_len = int.from_bytes(raw_payload[2:4], "big")
            tx_id = raw_payload[8:20].hex()
            
            names = {
                0x0001: "Binding Request",
                0x0101: "Binding Success Response",
                0x0111: "Binding Error Response",
                0x0003: "Allocate Request",
                0x0103: "Allocate Success Response",
                0x0004: "Refresh Request",
                0x0104: "Refresh Success Response",
            }
            msg_name = names.get(msg_type, f"Unknown STUN Type (0x{msg_type:04x})")
            return {
                "rule_name": self.name,
                "category": self.category,
                "severity": self.severity,
                "description": self.description,
                "matched_text": f"STUN {msg_name}",
                "extracted_fields": {
                    "stun_message_type": f"0x{msg_type:04x}",
                    "stun_message_name": msg_name,
                    "message_length_bytes": msg_len,
                    "transaction_id": tx_id
                }
            }
        return None

class RTPStructuredRule(DPIRule):
    def __init__(self):
        super().__init__(
            name="RTP Stream Traffic",
            category="VoIP",
            severity="Info",
            description="Identified Real-time Transport Protocol (RTP) packet structure."
        )

    def match(self, packet: dict, raw_payload: bytes | None) -> dict | None:
        if not raw_payload or len(raw_payload) < 12:
            return None
        
        # Check version: First 2 bits (version = 2)
        version = (raw_payload[0] & 0xC0) >> 6
        if version != 2:
            return None
            
        # Common RTP checks
        payload_type = raw_payload[1] & 0x7F
        seq_num = int.from_bytes(raw_payload[2:4], "big")
        timestamp = int.from_bytes(raw_payload[4:8], "big")
        ssrc = int.from_bytes(raw_payload[8:12], "big")
        
        # Filter out false positives (Payload Type is usually between 0-34 or 96-127)
        if (0 <= payload_type <= 34) or (96 <= payload_type <= 127):
            return {
                "rule_name": self.name,
                "category": self.category,
                "severity": self.severity,
                "description": self.description,
                "matched_text": f"RTP Pt={payload_type} SSRC={ssrc}",
                "extracted_fields": {
                    "rtp_version": version,
                    "payload_type": payload_type,
                    "sequence_number": seq_num,
                    "timestamp": timestamp,
                    "ssrc": ssrc
                }
            }
        return None

class TLSClientHelloRule(DPIRule):
    def __init__(self):
        super().__init__(
            name="TLS Client Hello Handshake",
            category="Network",
            severity="Info",
            description="Parsed ClientHello message containing SNI and handshake specifications."
        )

    def match(self, packet: dict, raw_payload: bytes | None) -> dict | None:
        if not raw_payload or len(raw_payload) < 43: # TLS record header (5) + Handshake header (4) + ClientHello min bytes
            return None
        
        # TLS Record Type: Handshake (0x16)
        if raw_payload[0] != 0x16:
            return None
            
        # TLS Major/Minor version: 3.x
        if raw_payload[1] != 0x03 or raw_payload[2] not in {0x00, 0x01, 0x02, 0x03, 0x04}:
            return None
            
        # Handshake Type: Client Hello (0x01)
        if raw_payload[5] != 0x01:
            return None
            
        # Let's extract the Server Name Indication (SNI) extension safely
        sni = self._extract_sni(raw_payload)
        
        extracted = {
            "tls_record_version": f"3.{raw_payload[2]}"
        }
        if sni:
            extracted["sni_server_name"] = sni
            matched = f"TLS SNI: {sni}"
        else:
            matched = "TLS ClientHello Handshake"
            
        return {
            "rule_name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "matched_text": matched,
            "extracted_fields": extracted
        }

    def _extract_sni(self, data: bytes) -> str | None:
        try:
            # Skip TLS Record Header (5 bytes)
            # Handshake Header (4 bytes)
            # Client Version (2 bytes)
            # Random (32 bytes)
            pos = 5 + 4 + 2 + 32
            
            # Session ID
            session_id_len = data[pos]
            pos += 1 + session_id_len
            
            if pos + 2 > len(data): return None
            # Cipher Suites
            cipher_len = int.from_bytes(data[pos:pos+2], "big")
            pos += 2 + cipher_len
            
            if pos + 1 > len(data): return None
            # Compression Methods
            comp_len = data[pos]
            pos += 1 + comp_len
            
            if pos + 2 > len(data): return None
            # Extensions length
            extensions_len = int.from_bytes(data[pos:pos+2], "big")
            pos += 2
            
            end_pos = pos + extensions_len
            while pos + 4 <= end_pos and pos + 4 <= len(data):
                ext_type = int.from_bytes(data[pos:pos+2], "big")
                ext_len = int.from_bytes(data[pos+2:pos+4], "big")
                pos += 4
                
                # SNI extension type is 0x0000
                if ext_type == 0:
                    # Parse Server Name List
                    if pos + 2 <= len(data):
                        list_len = int.from_bytes(data[pos:pos+2], "big")
                        inner_pos = pos + 2
                        if inner_pos + 3 <= len(data):
                            name_type = data[inner_pos]
                            name_len = int.from_bytes(data[inner_pos+1:inner_pos+3], "big")
                            if name_type == 0 and inner_pos + 3 + name_len <= len(data):
                                return data[inner_pos+3:inner_pos+3+name_len].decode("utf-8", errors="ignore")
                pos += ext_len
        except Exception:
            pass
        return None

class CloudAttributionRule(DPIRule):
    def __init__(self):
        super().__init__(
            name="Cloud Host Attribution",
            category="Cloud",
            severity="Info",
            description="Identified traffic associated with public cloud provider infrastructure."
        )

    def match(self, packet: dict, raw_payload: bytes | None) -> dict | None:
        asn_org = str(packet.get("asn_org") or packet.get("isp") or "").upper()
        host = str(packet.get("hostname") or "").upper()
        
        provider = None
        if "AMAZON" in asn_org or "AWS" in asn_org:
            provider = "AWS"
        elif "GOOGLE" in asn_org or "GCP" in asn_org:
            provider = "Google Cloud"
        elif "MICROSOFT" in asn_org or "AZURE" in asn_org:
            provider = "Microsoft Azure"
        elif "CLOUDFLARE" in asn_org:
            provider = "Cloudflare"
            
        if provider:
            return {
                "rule_name": self.name,
                "category": self.category,
                "severity": self.severity,
                "description": self.description,
                "matched_text": f"Attributed to {provider}",
                "extracted_fields": {
                    "cloud_provider": provider,
                    "resolved_org": packet.get("asn_org") or packet.get("isp")
                }
            }
        return None

class BasicAuthCredentialRule(DPIRule):
    def __init__(self):
        super().__init__(
            name="Base64 Basic Authentication",
            category="Credentials",
            severity="Medium",
            description="Detected Base64-encoded credential transmission inside HTTP headers."
        )

    def match(self, packet: dict, raw_payload: bytes | None) -> dict | None:
        preview = packet.get("payload_preview") or ""
        if not preview:
            return None
        
        match_obj = re.search(r"Authorization:\s*Basic\s*([a-zA-Z0-9+/=]+)", preview, re.IGNORECASE)
        if match_obj:
            encoded_str = match_obj.group(1)
            try:
                decoded_str = base64.b64decode(encoded_str).decode("utf-8", errors="ignore")
                if ":" in decoded_str:
                    username, password = decoded_str.split(":", 1)
                    # Mask the password for security
                    masked_password = password[0] + "*" * (len(password) - 1) if password else ""
                    return {
                        "rule_name": self.name,
                        "category": self.category,
                        "severity": self.severity,
                        "description": self.description,
                        "matched_text": f"Credential Leak (User: {username})",
                        "extracted_fields": {
                            "username": username,
                            "password_masked": masked_password
                        }
                    }
            except Exception:
                pass
        return None


# --- Engine Registry ---

class DPIEngine:
    def __init__(self):
        self.rules = []
        self._register_rules()

    def _register_rules(self):
        # 1. Credentials
        self.rules.append(BasicAuthCredentialRule())
        self.rules.append(RegexRule(
            name="Plaintext Password Field",
            category="Credentials",
            severity="Medium",
            description="Identified credentials exposed inside body parameters or queries.",
            pattern=r"(?:password|passwd|pwd|secret|token)\s*[:=]\s*[\"']?([a-zA-Z0-9_@#$%-]+)[\"']?"
        ))

        # 2. Secrets
        self.rules.append(RegexRule(
            name="RSA Private Key Leak",
            category="Secrets",
            severity="High",
            description="Detected an exposed PEM RSA Private Key string.",
            pattern=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"
        ))
        self.rules.append(RegexRule(
            name="Slack API Token Leak",
            category="Secrets",
            severity="High",
            description="Slack Bot/User API Token identified in traffic.",
            pattern=r"xox[bopr]-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}"
        ))
        self.rules.append(RegexRule(
            name="AWS Access Key ID",
            category="Secrets",
            severity="Medium",
            description="AWS Management Console Credential string detected.",
            pattern=r"\bAKIA[0-9A-Z]{16}\b"
        ))

        # 3. Web Attacks
        self.rules.append(RegexRule(
            name="SQL Injection (SQLi) Attempt",
            category="Web Attacks",
            severity="High",
            description="Common SQL Injection statements detected in query strings.",
            pattern=r"UNION\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM"
        ))
        self.rules.append(RegexRule(
            name="Cross-Site Scripting (XSS)",
            category="Web Attacks",
            severity="High",
            description="Client-side script tags or javascript URI parameters detected.",
            pattern=r"<script\b[^>]*>|javascript:|onerror\s*="
        ))

        # 4. VoIP Rules
        self.rules.append(STUNStructuredRule())
        self.rules.append(RTPStructuredRule())
        self.rules.append(RegexRule(
            name="SIP VoIP Protocol Signature",
            category="VoIP",
            severity="Info",
            description="Identified Session Initiation Protocol (SIP) command verb.",
            pattern=r"\b(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY)\s+sip:"
        ))

        # 5. Network Rules
        self.rules.append(TLSClientHelloRule())
        
        # 6. Cloud Rules
        self.rules.append(CloudAttributionRule())

    def inspect_packet(self, packet: dict, raw_payload: bytes | None = None) -> list[dict]:
        alerts = []
        for rule in self.rules:
            try:
                alert = rule.match(packet, raw_payload)
                if alert:
                    alerts.append(alert)
            except Exception:
                pass
        return alerts

# Singleton instance
dpi_engine = DPIEngine()
