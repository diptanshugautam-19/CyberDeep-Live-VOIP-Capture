import sys
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.attribution_engine import AttributionEngine, OutputFormatter, IceState

class TestAttributionEngine(unittest.TestCase):
    def test_stun_binding_response_only(self):
        engine = AttributionEngine()
        engine.ingest_parsed_logs(
            stun_packets=[{
                "message_name": "Binding Success Response",
                "source_ip": "203.0.113.10",
                "source_port": 3478,
                "destination_ip": "192.168.1.50",
                "destination_port": 1234,
                "xor_mapped_address": {"ip": "192.168.1.50", "port": 1234}
            }],
            rtp_packets=[],
            sip_messages=[]
        )
        summary = engine.analyze()
        self.assertIsNone(summary.remote_ip)
        self.assertEqual(summary.confidence, 0)
        self.assertIn("Insufficient protocol evidence", summary.reason)

    def test_sdp_only_host_candidates_no_ice(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 1234 RTP/AVP 0\r\n"
            "a=candidate:1 1 udp 2130706431 192.168.1.50 1234 typ host\r\n"
        )
        summary = engine.analyze()
        self.assertIsNone(summary.remote_ip)
        self.assertEqual(summary.confidence, 0)
        self.assertIn("Insufficient protocol evidence", summary.reason)

    def test_direct_p2p_with_rtp(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 1234 RTP/AVP 0\r\n"
            "a=candidate:1 1 udp 2130706431 192.168.1.50 1234 typ host\r\n"
            "a=candidate:2 1 udp 1694498815 203.0.113.10 5678 typ srflx\r\n"
        )
        engine.ingest_parsed_logs(
            stun_packets=[],
            rtp_packets=[{
                "ssrc": 12345,
                "payload_type": 0,
                "source_ip": "203.0.113.10",
                "source_port": 5678,
                "destination_ip": "192.168.1.50",
                "destination_port": 1234,
                "timestamp": 1.0
            }],
            sip_messages=[]
        )
        summary = engine.analyze()
        self.assertEqual(summary.remote_ip, "203.0.113.10")
        self.assertEqual(summary.confidence, 100)
        self.assertEqual(summary.media_path, "Peer-to-Peer")

    def test_turn_relay_selected(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 1234 RTP/AVP 0\r\n"
            "a=candidate:1 1 udp 2130706431 192.168.1.50 1234 typ host\r\n"
            "a=candidate:2 1 udp 1694498815 198.51.100.20 3478 typ relay\r\n"
        )
        engine.ingest_parsed_logs(
            stun_packets=[{
                "message_name": "Allocate Success Response",
                "source_ip": "198.51.100.20",
                "source_port": 3478,
                "destination_ip": "192.168.1.50",
                "destination_port": 1234,
                "xor_relayed_address": {"ip": "198.51.100.20", "port": 50000},
                "use_candidate": True
            }],
            rtp_packets=[],
            sip_messages=[]
        )
        summary = engine.analyze()
        self.assertIsNone(summary.remote_ip)
        self.assertEqual(summary.confidence, 0)
        self.assertEqual(summary.media_path, "TURN Relay")
        self.assertEqual(summary.relay_ip, "198.51.100.20")

    def test_selected_srflx_candidate_no_rtp(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 1234 RTP/AVP 0\r\n"
            "a=candidate:1 1 udp 2130706431 192.168.1.50 1234 typ host\r\n"
            "a=candidate:2 1 udp 1694498815 203.0.113.10 5678 typ srflx\r\n"
        )
        engine.ingest_parsed_logs(
            stun_packets=[{
                "message_name": "Binding Success Response",
                "source_ip": "203.0.113.10",
                "source_port": 5678,
                "destination_ip": "192.168.1.50",
                "destination_port": 1234,
                "use_candidate": True
            }],
            rtp_packets=[],
            sip_messages=[]
        )
        summary = engine.analyze()
        self.assertEqual(summary.remote_ip, "203.0.113.10")
        self.assertEqual(summary.confidence, 90)
        self.assertEqual(summary.media_path, "Peer-to-Peer")

    def test_sdp_candidate_not_selected(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 1234 RTP/AVP 0\r\n"
            "a=candidate:1 1 udp 2130706431 192.168.1.50 1234 typ host\r\n"
            "a=candidate:2 1 udp 1694498815 203.0.113.10 5678 typ srflx\r\n"
        )
        summary = engine.analyze()
        self.assertIsNone(summary.remote_ip)
        self.assertEqual(summary.confidence, 0)
        self.assertEqual(summary.reason, "Candidate Only — Not Confirmed")

    def test_rtp_from_turn_relay_ip(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 1234 RTP/AVP 0\r\n"
            "a=candidate:1 1 udp 2130706431 192.168.1.50 1234 typ host\r\n"
            "a=candidate:2 1 udp 1694498815 198.51.100.20 3478 typ relay\r\n"
        )
        engine.ingest_parsed_logs(
            stun_packets=[{
                "message_name": "Allocate Success Response",
                "source_ip": "198.51.100.20",
                "source_port": 3478,
                "destination_ip": "192.168.1.50",
                "destination_port": 1234,
                "xor_relayed_address": {"ip": "198.51.100.20", "port": 50000}
            }],
            rtp_packets=[{
                "ssrc": 12345,
                "payload_type": 0,
                "source_ip": "198.51.100.20",
                "source_port": 50000,
                "destination_ip": "192.168.1.50",
                "destination_port": 1234,
                "timestamp": 1.0
            }],
            sip_messages=[]
        )
        summary = engine.analyze()
        self.assertIsNone(summary.remote_ip)
        self.assertEqual(summary.confidence, 0)
        self.assertEqual(summary.media_path, "TURN Relay")

    def test_quic_to_meta_infrastructure(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 1234 RTP/AVP 0\r\n"
        )
        engine.ingest_packet(b"\xC0\x01\x02\x03\x04", "157.240.240.35", 443, "192.168.1.50", 1234, 1.0)
        summary = engine.analyze()
        self.assertIsNone(summary.remote_ip)
        self.assertEqual(summary.confidence, 0)
        self.assertEqual(summary.media_path, "Provider Infrastructure")
        self.assertEqual(summary.provider, "Meta")

    def test_sdp_media_port_mapping(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "m=audio 9000 RTP/AVP 96\r\n"
            "a=rtpmap:96 OPUS/48000/2\r\n"
            "m=video 9002 RTP/AVP 97\r\n"
            "a=rtpmap:97 VP8/90000\r\n"
        )
        # SSRC 111 uses port 9000 (audio)
        engine.rtp_parser.parse_packet(b"\x80\x60\x00\x01\x00\x00\x00\x00\x00\x00\x00\x6F", "203.0.113.10", 9000, "192.168.1.50", 9000, 1.0, {"192.168.1.50"})
        # SSRC 222 uses port 9002 (video)
        engine.rtp_parser.parse_packet(b"\x80\x61\x00\x01\x00\x00\x00\x00\x00\x00\x00\xDE", "203.0.113.10", 9002, "192.168.1.50", 9002, 1.0, {"192.168.1.50"})
        
        audio_stream = engine.rtp_parser.streams[111]
        video_stream = engine.rtp_parser.streams[222]
        
        self.assertEqual(engine._classify_stream_type(audio_stream), "Audio")
        self.assertEqual(engine._classify_stream_type(video_stream), "Video")

    def test_ice_username_correlation(self):
        engine = AttributionEngine()
        engine.ingest_sdp(
            "v=0\r\n"
            "c=IN IP4 192.168.1.50\r\n"
            "a=ice-ufrag:caller_ufrag\r\n"
        )
        # Stun packet with remote:local username matching ice-ufrag
        engine.ingest_parsed_logs(
            stun_packets=[{
                "message_name": "Binding Success Response",
                "source_ip": "203.0.113.10",
                "source_port": 3478,
                "destination_ip": "192.168.1.50",
                "destination_port": 1234,
                "remote_ufrag": "caller_ufrag",
                "local_ufrag": "callee_ufrag"
            }],
            rtp_packets=[],
            sip_messages=[]
        )
        self.assertTrue(engine.correlation.matches_ufrag("caller_ufrag"))
        self.assertFalse(engine.correlation.matches_ufrag("unknown_ufrag"))

    def test_quic_packet_validation_strict(self):
        engine = AttributionEngine()
        # Invalid QUIC header packet (plain HTTP/TLS or short)
        engine.ingest_packet(b"\x16\x03\x01\x00\x05", "157.240.240.35", 443, "192.168.1.50", 1234, 1.0)
        self.assertEqual(len(engine.quic_detector.quic_endpoints), 0)
        
        # Valid QUIC long header packet (0xC0)
        engine.ingest_packet(b"\xC0\x00\x00\x00\x01", "157.240.240.35", 443, "192.168.1.50", 1234, 1.0)
        self.assertEqual(len(engine.quic_detector.quic_endpoints), 2)

if __name__ == "__main__":
    unittest.main()
