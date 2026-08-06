import hashlib
import struct
import logging
from typing import Tuple, Optional, Dict

logger = logging.getLogger(__name__)

def is_grease(val: int) -> bool:
    """Checks if the TLS value is a GREASE value."""
    if (val & 0x0F0F) == 0x0A0A:
        return True
    return False

def parse_tls_client_hello(payload: bytes) -> Optional[Dict[str, str]]:
    """
    Parses a TLS ClientHello payload to compute JA3 and JA4 client fingerprints.
    Returns a dict with "ja3" and "ja4" keys or None.
    """
    try:
        if len(payload) < 45:
            return None
            
        # Check TLS Record Header: 0x16 (Handshake) + 0x03 (TLS Major)
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None
            
        # Handshake Type must be 1 (ClientHello)
        hs_offset = 5
        if hs_offset >= len(payload) or payload[hs_offset] != 0x01:
            return None
            
        # Version (2 bytes)
        version_offset = hs_offset + 4
        if version_offset + 2 > len(payload):
            return None
        tls_version = struct.unpack("!H", payload[version_offset:version_offset+2])[0]
        
        # Session ID length (1 byte)
        session_id_len_offset = version_offset + 34
        if session_id_len_offset >= len(payload):
            return None
        session_id_len = payload[session_id_len_offset]
        
        # Cipher Suites
        cipher_suites_offset = session_id_len_offset + 1 + session_id_len
        if cipher_suites_offset + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack("!H", payload[cipher_suites_offset:cipher_suites_offset+2])[0]
        
        ciphers_start = cipher_suites_offset + 2
        if ciphers_start + cipher_suites_len > len(payload):
            return None
            
        ciphers_data = payload[ciphers_start:ciphers_start + cipher_suites_len]
        ciphers_list = []
        ciphers_ja4_list = []
        for i in range(0, len(ciphers_data), 2):
            if i + 2 <= len(ciphers_data):
                cipher = struct.unpack("!H", ciphers_data[i:i+2])[0]
                if not is_grease(cipher):
                    ciphers_list.append(str(cipher))
                    ciphers_ja4_list.append(f"{cipher:04x}")
                    
        # Compression Methods
        compression_offset = ciphers_start + cipher_suites_len
        if compression_offset + 1 > len(payload):
            return None
        compression_len = payload[compression_offset]
        
        # Extensions
        extensions_offset = compression_offset + 1 + compression_len
        extensions_list = []
        curves_list = []
        formats_list = []
        
        extensions_ja4_list = []
        sni_present = "d"
        alpn_val = "00"
        
        if extensions_offset + 2 <= len(payload):
            extensions_len = struct.unpack("!H", payload[extensions_offset:extensions_offset+2])[0]
            ext_start = extensions_offset + 2
            if ext_start + extensions_len <= len(payload):
                ext_data = payload[ext_start:ext_start + extensions_len]
                idx = 0
                while idx + 4 <= len(ext_data):
                    ext_type, ext_len = struct.unpack("!HH", ext_data[idx:idx+4])
                    if not is_grease(ext_type):
                        extensions_list.append(str(ext_type))
                        extensions_ja4_list.append(f"{ext_type:04x}")
                        
                    val_start = idx + 4
                    if val_start + ext_len > len(ext_data):
                        break
                        
                    ext_val = ext_data[val_start:val_start + ext_len]
                    
                    # SNI (Extension 0)
                    if ext_type == 0:
                        sni_present = "i"
                        
                    # Supported Groups (Extension 10)
                    elif ext_type == 10:
                        if len(ext_val) >= 2:
                            groups_len = struct.unpack("!H", ext_val[0:2])[0]
                            groups_data = ext_val[2:2+groups_len]
                            for g in range(0, len(groups_data), 2):
                                if g + 2 <= len(groups_data):
                                    group = struct.unpack("!H", groups_data[g:g+2])[0]
                                    if not is_grease(group):
                                        curves_list.append(str(group))
                                        
                    # EC Point Formats (Extension 11)
                    elif ext_type == 11:
                        if len(ext_val) >= 1:
                            formats_len = ext_val[0]
                            formats_data = ext_val[1:1+formats_len]
                            for f in formats_data:
                                formats_list.append(str(f))
                                
                    # ALPN (Extension 16)
                    elif ext_type == 16:
                        if len(ext_val) >= 4:
                            alpn_len = struct.unpack("!H", ext_val[0:2])[0]
                            if alpn_len > 0 and len(ext_val) >= 2 + alpn_len:
                                first_proto_len = ext_val[2]
                                if first_proto_len > 0 and len(ext_val) >= 3 + first_proto_len:
                                    first_proto = ext_val[3:3+first_proto_len].decode('utf-8', errors='replace')
                                    alpn_val = first_proto[:2].ljust(2, '0')[:2]
                                    
                    # Supported Versions (Extension 43 / 0x002B)
                    elif ext_type == 43:
                        if len(ext_val) >= 2:
                            versions_len = ext_val[0]
                            versions_data = ext_val[1:1+versions_len]
                            for v_idx in range(0, len(versions_data), 2):
                                if v_idx + 2 <= len(versions_data):
                                    supp_ver = struct.unpack("!H", versions_data[v_idx:v_idx+2])[0]
                                    if not is_grease(supp_ver) and supp_ver > tls_version:
                                        tls_version = supp_ver

                    idx = val_start + ext_len

        # 1. JA3 Client Fingerprint
        ja3_str = ",".join([
            str(tls_version),
            "-".join(ciphers_list),
            "-".join(extensions_list),
            "-".join(curves_list),
            "-".join(formats_list)
        ])
        ja3_hash = hashlib.md5(ja3_str.encode('utf-8')).hexdigest()
        
        # 2. JA4 Client Fingerprint
        # Part A
        ver_str = "13" if tls_version >= 0x0304 else ("12" if tls_version == 0x0303 else "10")
        ciphers_cnt = f"{min(len(ciphers_ja4_list), 99):02d}"
        exts_cnt = f"{min(len(extensions_ja4_list), 99):02d}"
        part_a = f"t{ver_str}{sni_present}{ciphers_cnt}{exts_cnt}{alpn_val}"
        
        # Part B
        sorted_ciphers = sorted(ciphers_ja4_list)
        ciphers_hash = hashlib.sha256(",".join(sorted_ciphers).encode()).hexdigest()[:12] if sorted_ciphers else "000000000000"
        
        # Part C
        sorted_exts = sorted(extensions_ja4_list)
        exts_hash = hashlib.sha256(",".join(sorted_exts).encode()).hexdigest()[:12] if sorted_exts else "000000000000"
        
        ja4_hash = f"{part_a}_{ciphers_hash}_{exts_hash}"
        
        return {"ja3": ja3_hash, "ja4": ja4_hash}
        
    except Exception as e:
        logger.debug(f"Error parsing TLS ClientHello for Client fingerprints: {e}")
        return None

def parse_tls_server_hello(payload: bytes) -> Optional[Dict[str, str]]:
    """
    Parses a TLS ServerHello payload to compute JA3S and JA4S server fingerprints.
    Returns a dict with "ja3s" and "ja4s" keys or None.
    """
    try:
        if len(payload) < 45:
            return None
            
        # Check TLS Record Header: 0x16 (Handshake) + 0x03 (TLS Major)
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None
            
        # Handshake Type must be 2 (ServerHello)
        hs_offset = 5
        if hs_offset >= len(payload) or payload[hs_offset] != 0x02:
            return None
            
        # Version (2 bytes)
        version_offset = hs_offset + 4
        if version_offset + 2 > len(payload):
            return None
        tls_version = struct.unpack("!H", payload[version_offset:version_offset+2])[0]
        
        # Session ID length (1 byte)
        session_id_len_offset = version_offset + 34
        if session_id_len_offset >= len(payload):
            return None
        session_id_len = payload[session_id_len_offset]
        
        # Cipher Suite chosen by server (exactly one cipher suite, 2 bytes)
        cipher_offset = session_id_len_offset + 1 + session_id_len
        if cipher_offset + 2 > len(payload):
            return None
        selected_cipher = struct.unpack("!H", payload[cipher_offset:cipher_offset+2])[0]
        
        # Compression Method (1 byte)
        compression_offset = cipher_offset + 2
        if compression_offset + 1 > len(payload):
            return None
        compression_method = payload[compression_offset]
        
        # Extensions
        extensions_offset = compression_offset + 1
        extensions_list = []
        extensions_ja4_list = []
        
        if extensions_offset + 2 <= len(payload):
            extensions_len = struct.unpack("!H", payload[extensions_offset:extensions_offset+2])[0]
            ext_start = extensions_offset + 2
            if ext_start + extensions_len <= len(payload):
                ext_data = payload[ext_start:ext_start + extensions_len]
                idx = 0
                while idx + 4 <= len(ext_data):
                    ext_type, ext_len = struct.unpack("!HH", ext_data[idx:idx+4])
                    if not is_grease(ext_type):
                        extensions_list.append(str(ext_type))
                        extensions_ja4_list.append(f"{ext_type:04x}")
                    idx = idx + 4 + ext_len

        # 1. JA3S Server Fingerprint
        ja3s_str = ",".join([
            str(tls_version),
            str(selected_cipher),
            "-".join(extensions_list)
        ])
        ja3s_hash = hashlib.md5(ja3s_str.encode('utf-8')).hexdigest()
        
        # 2. JA4S Server Fingerprint
        # Part A: protocol + tls version + s (server) + 00 (no SNI) + 01 (1 cipher selected) + extensions count + 00 (no ALPN)
        ver_str = "13" if tls_version >= 0x0304 else ("12" if tls_version == 0x0303 else "10")
        exts_cnt = f"{min(len(extensions_ja4_list), 99):02d}"
        part_a = f"t{ver_str}s0001{exts_cnt}00"
        
        # Part B: Single cipher SHA256 hashed
        cipher_hex = f"{selected_cipher:04x}"
        cipher_hash = hashlib.sha256(cipher_hex.encode()).hexdigest()[:12]
        
        # Part C: Extensions SHA256 hashed
        sorted_exts = sorted(extensions_ja4_list)
        exts_hash = hashlib.sha256(",".join(sorted_exts).encode()).hexdigest()[:12] if sorted_exts else "000000000000"
        
        ja4s_hash = f"{part_a}_{cipher_hash}_{exts_hash}"
        
        return {"ja3s": ja3s_hash, "ja4s": ja4s_hash}
        
    except Exception as e:
        logger.debug(f"Error parsing TLS ServerHello for Server fingerprints: {e}")
        return None

def get_tls_fingerprints(payload: bytes) -> Dict[str, str]:
    """Helper to detect and return JA3, JA4, JA3S, and JA4S fingerprints from raw payload bytes."""
    fingerprints = {}
    
    # Check if ClientHello or ServerHello
    client_res = parse_tls_client_hello(payload)
    if client_res:
        fingerprints.update(client_res)
        
    server_res = parse_tls_server_hello(payload)
    if server_res:
        fingerprints.update(server_res)
        
    return fingerprints

def parse_ssh_hassh(payload: bytes) -> Optional[Dict[str, str]]:
    """
    Parses SSH KEXINIT payload to calculate HASSH (Client) or HASSHServer (Server) fingerprints.
    HASSH format: MD5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms)
    """
    try:
        if len(payload) < 20 or not (payload.startswith(b"SSH-") or payload[0] == 20):
            return None

        # Handle SSH Key Exchange Init (packet type 20)
        idx = payload.find(b"\x14")  # 0x14 = 20 (SSH_MSG_KEXINIT)
        if idx == -1 or idx + 17 > len(payload):
            return None

        offset = idx + 1 + 16  # Skip msg type (1 byte) + cookie (16 bytes)

        def read_ssh_string(buf: bytes, off: int) -> tuple[str, int]:
            if off + 4 > len(buf):
                return "", off
            str_len = struct.unpack("!I", buf[off:off+4])[0]
            off += 4
            if str_len > 8192 or off + str_len > len(buf):
                return "", off
            s = buf[off:off+str_len].decode("utf-8", errors="ignore")
            return s, off + str_len

        kex_algo, offset = read_ssh_string(payload, offset)
        server_host_key_algo, offset = read_ssh_string(payload, offset)
        enc_c2s, offset = read_ssh_string(payload, offset)
        enc_s2c, offset = read_ssh_string(payload, offset)
        mac_c2s, offset = read_ssh_string(payload, offset)
        mac_s2c, offset = read_ssh_string(payload, offset)
        comp_c2s, offset = read_ssh_string(payload, offset)
        comp_s2c, offset = read_ssh_string(payload, offset)

        if not kex_algo or not enc_c2s:
            return None

        # Build Client HASSH
        hassh_raw = f"{kex_algo};{enc_c2s};{mac_c2s};{comp_c2s}"
        hassh = hashlib.md5(hassh_raw.encode("utf-8")).hexdigest()

        # Build Server HASSHServer
        hassh_server_raw = f"{kex_algo};{enc_s2c};{mac_s2c};{comp_s2c}"
        hassh_server = hashlib.md5(hassh_server_raw.encode("utf-8")).hexdigest()

        return {
            "hassh": hassh,
            "hassh_server": hassh_server,
            "ssh_kex": kex_algo,
            "ssh_enc": enc_c2s
        }
    except Exception as e:
        logger.debug(f"Error parsing SSH HASSH: {e}")
        return None

