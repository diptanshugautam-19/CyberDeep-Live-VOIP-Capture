import unittest
from app.analysis.attribution_engine import StunFamilyMessage, _is_bogon_or_invalid

class TestAttributionEngine(unittest.TestCase):
    def test_is_bogon_or_invalid(self):
        self.assertTrue(_is_bogon_or_invalid("127.0.0.1"))
        self.assertTrue(_is_bogon_or_invalid("224.0.0.1"))
        self.assertTrue(_is_bogon_or_invalid("invalid_ip"))
        self.assertFalse(_is_bogon_or_invalid("192.168.1.50"))
        self.assertFalse(_is_bogon_or_invalid("8.8.8.8"))

    def test_stun_family_message_invalid(self):
        msg = StunFamilyMessage(b"short", "1.1.1.1", 1234, "2.2.2.2", 3478, 100.0)
        self.assertFalse(msg.is_valid)

if __name__ == "__main__":
    unittest.main()
