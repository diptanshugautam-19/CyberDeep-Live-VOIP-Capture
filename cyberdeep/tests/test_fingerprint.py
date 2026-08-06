import unittest
from app.core.fingerprint import parse_tls_client_hello, parse_ssh_hassh

class TestFingerprint(unittest.TestCase):
    def test_tls_client_hello_invalid_payload(self):
        self.assertIsNone(parse_tls_client_hello(b""))
        self.assertIsNone(parse_tls_client_hello(b"12345"))

    def test_ssh_hassh_invalid(self):
        self.assertIsNone(parse_ssh_hassh(b""))
        self.assertIsNone(parse_ssh_hassh(b"NOT_SSH_FRAME"))

    def test_ssh_hassh_valid_kexinit(self):
        kex_algo = b"diffie-hellman-group1-sha1"
        enc_c2s = b"aes128-cbc"
        enc_s2c = b"aes128-cbc"
        mac_c2s = b"hmac-sha1"
        mac_s2c = b"hmac-sha1"
        comp_c2s = b"none"
        comp_s2c = b"none"
        
        def pack_str(s: bytes) -> bytes:
            return len(s).to_bytes(4, "big") + s

        payload = (
            b"SSH-2.0-OpenSSH_8.0\r\n"
            b"\x14" + b"\x00" * 16 +
            pack_str(kex_algo) +
            pack_str(b"ssh-rsa") +
            pack_str(enc_c2s) +
            pack_str(enc_s2c) +
            pack_str(mac_c2s) +
            pack_str(mac_s2c) +
            pack_str(comp_c2s) +
            pack_str(comp_s2c) +
            pack_str(b"") +
            pack_str(b"")
        )
        res = parse_ssh_hassh(payload)
        self.assertIsNotNone(res)
        self.assertIn("hassh", res)
        self.assertIn("hassh_server", res)

if __name__ == "__main__":
    unittest.main()
