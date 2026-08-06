import unittest
import struct
from app.protocols.stun import parse_stun_packet, decode_xor_mapped_address, parse_mapped_address, STUN_MAGIC_COOKIE

class TestStunParser(unittest.TestCase):
    def test_decode_xor_mapped_address_ipv4(self):
        # STUN Attribute Header: Type=0x0020 (XOR-MAPPED-ADDRESS), Length=8
        # Value bytes: reserved (1 byte) = 0x00, family (1 byte) = 0x01 (IPv4),
        # port (2 bytes) = 0x1234 ^ (STUN_MAGIC_COOKIE >> 16)
        # ip (4 bytes) = 192.168.1.1 ^ STUN_MAGIC_COOKIE
        magic = STUN_MAGIC_COOKIE
        port = 1234
        ip_bytes = bytes([192, 168, 1, 1])
        ip_int = struct.unpack(">I", ip_bytes)[0]
        
        xor_port = port ^ (magic >> 16)
        xor_ip = ip_int ^ magic
        
        # Build 8-byte XOR-MAPPED-ADDRESS value memoryview
        val = struct.pack(">BBHI", 0, 1, xor_port, xor_ip)
        mv = memoryview(val)
        
        decoded_ip, decoded_port = decode_xor_mapped_address(mv, b"123456789012")
        self.assertEqual(decoded_ip, "192.168.1.1")
        self.assertEqual(decoded_port, 1234)

    def test_parse_mapped_address_ipv4(self):
        # MAPPED-ADDRESS value bytes: reserved (1 byte), family (1 byte) = 1, port (2 bytes) = 8080, IP (4 bytes) = 1.2.3.4
        val = struct.pack(">BBH4s", 0, 1, 8080, bytes([1, 2, 3, 4]))
        mv = memoryview(val)
        
        decoded_ip, decoded_port = parse_mapped_address(mv)
        self.assertEqual(decoded_ip, "1.2.3.4")
        self.assertEqual(decoded_port, 8080)

if __name__ == "__main__":
    unittest.main()
