import sys
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.protocols.stun import decode_xor_mapped_address, parse_stun_packet
from app.protocols.rtp import parse_rtp_header, compute_qos_metrics
from app.protocols.sip import parse_sip_message, _parse_sdp_candidate as parse_sdp_candidate
from app.protocols.ice import IceCandidate, EndpointIdentity, IceStateMachine, resolve_endpoint_identity
from app.protocols.models import VoipSession, QosMetrics, RtpStream
from app.analysis.attribution import build_call_attribution
from app.analysis.graph_hooks import voip_session_to_graph


class TestVoipEngine(unittest.TestCase):

    def test_stun_xor_decoding(self):
        # IPv4 Direct
        ip, port = decode_xor_mapped_address(
            bytes([0x00]) + bytes.fromhex("0001") + bytes.fromhex("F523") + bytes.fromhex("E112A643"),
            bytes(12)
        )
        self.assertEqual(ip, "192.0.2.1")
        self.assertEqual(port, 54321)

        # IPv6 WebRTC
        ip, port = decode_xor_mapped_address(
            bytes([0x00]) + bytes.fromhex("0002") + bytes.fromhex("E312") + bytes.fromhex("0113A9FA6E0001EE2C26002600000027"),
            bytes.fromhex("6e0001ee2c26002600000026")
        )
        self.assertEqual(ip, "2001:db8::1")
        self.assertEqual(port, 49664)

    def test_ice_state_machine(self):
        sm = IceStateMachine()
        self.assertEqual(sm.state, "NEW")
        
        # Valid transition
        sm.transition_to("GATHERING")
        self.assertEqual(sm.state, "GATHERING")
        
        # Invalid transition should remain in GATHERING or fail gracefully
        sm.transition_to("COMPLETED")
        self.assertEqual(sm.state, "GATHERING")

        # Valid step
        sm.transition_to("CHECKING")
        self.assertEqual(sm.state, "CHECKING")

    def test_ice_attribution_resolution(self):
        candidates = [
            IceCandidate("u1", "host", "192.168.1.50", 1234, 100, "1", 0.0),
            IceCandidate("u1", "srflx", "203.0.113.5", 5678, 90, "1", 0.0),
            IceCandidate("u1", "relay", "198.51.100.10", 3478, 80, "1", 0.0),
        ]
        identity = resolve_endpoint_identity("u1", candidates)
        self.assertEqual(identity.private_ip, "192.168.1.50")
        self.assertEqual(identity.public_ip, "203.0.113.5")
        self.assertEqual(identity.relay_ip, "198.51.100.10")
        self.assertEqual(identity.attribution_confidence, "direct")

    def test_rtp_qos(self):
        seqs = [1, 2, 3, 4, 5]
        ts = [160, 320, 480, 640, 800]
        arrs = [0.0, 0.02, 0.04, 0.06, 0.08]
        pts = [0, 0, 0, 0, 0] # G.711 PCMU (8000Hz)

        qos = compute_qos_metrics(seqs, ts, arrs, pts)
        self.assertEqual(qos["packet_loss_pct"], 0.0)
        self.assertGreaterEqual(qos["mos_score"], 4.0)

    def test_sip_parsing(self):
        sip_payload = (
            b"INVITE sip:bob@biloxi.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
            b"To: Bob <sip:bob@biloxi.com>\r\n"
            b"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
            b"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
            b"Content-Type: application/sdp\r\n"
            b"\r\n"
            b"v=0\r\n"
            b"o=alice 2890844526 2890844526 IN IP4 host.atlanta.com\r\n"
            b"c=IN IP4 192.0.2.101\r\n"
            b"m=audio 49170 RTP/AVP 0\r\n"
            b"a=candidate:842232490 1 udp 1686052607 192.168.1.14 51234 typ host\r\n"
        )
        parsed = parse_sip_message(sip_payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["call_id"], "a84b4c76e66710@pc33.atlanta.com")
        self.assertEqual(parsed["method"], "INVITE")
        self.assertEqual(parsed["sdp_media_ip"], "192.0.2.101")
        self.assertEqual(parsed["sdp_media_port"], 49170)
        self.assertEqual(len(parsed["sdp_candidates"]), 1)
        self.assertEqual(parsed["sdp_candidates"][0]["ip"], "192.168.1.14")
        self.assertEqual(parsed["sdp_candidates"][0]["port"], 51234)

    def test_graph_export(self):
        session = VoipSession(
            call_id="call-xyz",
            caller=EndpointIdentity(ufrag="u1", private_ip="192.168.1.50", public_ip="203.0.113.5"),
            callee=EndpointIdentity(ufrag="u2", private_ip="192.168.2.80", public_ip="198.51.100.20", relay_ip="198.51.100.99"),
            turn_servers=["198.51.100.99:3478"]
        )
        graph = voip_session_to_graph(session)
        self.assertEqual(len(graph["nodes"]), 5)
        self.assertEqual(len(graph["edges"]), 3)


if __name__ == "__main__":
    unittest.main()
