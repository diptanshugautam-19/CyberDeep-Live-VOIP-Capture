import struct
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.protocols.stun import decode_xor_mapped_address

# Test vectors
test_cases = [
    {
        "name": "IPv4 — Direct (RFC 5389 Example)",
        "family": 1,  # IPv4
        "xor_port_bytes": bytes.fromhex("F523"),
        "xor_address_bytes": bytes.fromhex("E112A643"),
        "transaction_id": bytes(12),  # zeros, unused for IPv4
        "magic_cookie": 0x2112A442,
        "expected_ip": "192.0.2.1",
        "expected_port": 54321,
    },
    {
        "name": "IPv4 — Behind NAT",
        "family": 1,
        "xor_port_bytes": bytes.fromhex("EA48"),
        "xor_address_bytes": bytes.fromhex("EA13D512"),
        "transaction_id": bytes(12),
        "magic_cookie": 0x2112A442,
        "expected_ip": "203.1.113.80",
        "expected_port": 52058,
    },
    {
        "name": "IPv6 — WebRTC",
        "family": 2,  # IPv6
        "xor_port_bytes": bytes.fromhex("E312"),
        "xor_address_bytes": bytes.fromhex("0113A9FA6E0001EE2C26002600000027"),
        "transaction_id": bytes.fromhex("6e0001ee2c26002600000026"),
        "magic_cookie": 0x2112A442,
        "expected_ip": "2001:db8::1",
        "expected_port": 49664,
    },
]

def test_decode_xor_mapped_address():
    for tc in test_cases:
        print(f"Testing: {tc['name']}")
        
        # Construct attribute value (reserved + family + xor_port + xor_address)
        attr_value = (
            bytes([0x00]) +
            struct.pack('>H', tc['family']) +
            tc['xor_port_bytes'] +
            tc['xor_address_bytes']
        )
        
        # Decode
        ip, port = decode_xor_mapped_address(
            attr_value,
            tc['transaction_id'],
            tc['magic_cookie']
        )
        
        # Verify
        assert ip == tc['expected_ip'], f"IP mismatch: got {ip}, expected {tc['expected_ip']}"
        assert port == tc['expected_port'], f"Port mismatch: got {port}, expected {tc['expected_port']}"
        print(f"  [OK] {ip}:{port}")

if __name__ == "__main__":
    test_decode_xor_mapped_address()
    print("\nAll tests passed!")
