import unittest
from app.protocols.tcp_media import make_tcp_stream, detect_tcp_framing, process_websocket_frames, MAX_TCP_BUFFER_SIZE

class TestTcpMedia(unittest.TestCase):
    def test_tcp_framing_detection(self):
        self.assertEqual(detect_tcp_framing(b"GET /ws HTTP/1.1\r\nHost: localhost\r\n\r\n"), "websocket")
        self.assertEqual(detect_tcp_framing(b"INVITE sip:bob@192.168.1.1 SIP/2.0\r\n"), "sip")

    def test_websocket_fast_unmasking(self):
        stream = make_tcp_stream()
        mask_key = b"\x12\x34\x56\x78"
        original_text = b"REGISTER sip:192.168.1.1 SIP/2.0\r\n\r\n"
        masked_bytes = bytes(b ^ mask_key[i % 4] for i, b in enumerate(original_text))
        header = bytes([0x81, 0x80 | len(original_text)]) + mask_key
        stream['buffer'] = bytearray(header + masked_bytes)

        captured = []
        def on_sip(data, ip, port):
            captured.append(data)

        process_websocket_frames(stream, ("127.0.0.1", 5060), on_sip)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0], original_text)

if __name__ == "__main__":
    unittest.main()
