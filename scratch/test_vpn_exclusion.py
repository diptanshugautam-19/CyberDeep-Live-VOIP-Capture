import sys
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.vpn_classifier import ClassificationEngine, EndpointRole, ROLE_TIERS
from app.enrichment.pipeline import enrichment_gate, analyze_records
from app.protocols.models import VoipSession
from app.analysis.attribution import build_call_attribution


class TestVpnExclusion(unittest.TestCase):

    def test_signature_loader(self):
        engine = ClassificationEngine(Path("registry/interfaces"))
        self.assertGreaterEqual(len(engine.registry), 1)
        
        # Verify loader loaded the android_vpnservice signature correctly
        sig = next((s for s in engine.registry if s.id == "android_vpnservice"), None)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.role_on_match, EndpointRole.VPN_INTERFACE)
        self.assertEqual(len(sig.conditions), 6)

    def test_scoring_and_classification(self):
        engine = ClassificationEngine(Path("registry/interfaces"))
        
        # Synthetic records representing a clear PCAPdroid VPN pair (10.215.173.1 <=> 10.215.173.2)
        records = [
            {"source_ip": "10.215.173.1", "destination_ip": "10.215.173.2", "packet_count": 98, "protocol": "DNS", "destination_port": 53},
            {"source_ip": "10.215.173.2", "destination_ip": "10.215.173.1", "packet_count": 98, "protocol": "DNS", "source_port": 53},
            {"source_ip": "10.215.173.1", "destination_ip": "10.215.173.2", "packet_count": 2, "protocol": "STUN"},
        ]
        
        # Classify device IP
        role, confidence, matched_sig, paired_addr, evidence = engine.classify("10.215.173.1", records, "PCAPdroid_capture.pcap")
        
        self.assertEqual(role, EndpointRole.VPN_INTERFACE)
        self.assertEqual(matched_sig, "android_vpnservice")
        self.assertEqual(paired_addr, "10.215.173.2")
        self.assertGreaterEqual(confidence, 0.85)
        self.assertIn("RFC1918 address pair", evidence)
        self.assertIn("No ARP or link layer evidence (virtual interface signature)", evidence)

    def test_enrichment_gate(self):
        endpoints = [
            {"ip": "10.215.173.1", "role": "VPN_INTERFACE", "tier": 1},
            {"ip": "8.8.8.8", "role": "DNS_SERVER", "tier": 2},
            {"ip": "192.168.1.5", "role": "PRIVATE_NETWORK", "tier": 2},
            {"ip": "1.2.3.4", "role": "RTP_ENDPOINT", "tier": 3},
            {"ip": "5.6.7.8", "role": "UNKNOWN", "tier": 4},
        ]
        
        eligible, excluded = enrichment_gate(endpoints)
        
        eligible_ips = {ep["ip"] for ep in eligible}
        excluded_ips = {ep["ip"] for ep in excluded}
        
        self.assertIn("8.8.8.8", eligible_ips)
        self.assertIn("192.168.1.5", eligible_ips)
        self.assertIn("1.2.3.4", eligible_ips)
        
        self.assertIn("10.215.173.1", excluded_ips)
        self.assertIn("5.6.7.8", excluded_ips)

    def test_build_call_attribution_integration(self):
        session = VoipSession(call_id="session-test-pcapdroid")
        
        stun_packets = [
            {"source_ip": "10.215.173.1", "destination_ip": "10.215.173.2", "packet_count": 10, "protocol": "STUN", "message_name": "Binding Request"},
            {"source_ip": "10.215.173.2", "destination_ip": "10.215.173.1", "packet_count": 10, "protocol": "STUN", "message_name": "Binding Success Response"},
        ]
        rtp_packets = [
            {"source_ip": "10.215.173.1", "destination_ip": "10.215.173.2", "packet_count": 100, "protocol": "RTP", "ssrc": 12345},
        ]
        sip_messages = [
            {"source_ip": "10.215.173.1", "destination_ip": "10.215.173.2", "packet_count": 2, "protocol": "SIP", "method": "INVITE"},
        ]
        
        session = build_call_attribution(session, stun_packets, rtp_packets, sip_messages)
        
        # Verify endpoints were classified
        self.assertGreater(len(session.endpoints), 0)
        
        # Verify 10.215.173.1 and 10.215.173.2 endpoints exist and are classified as VPN_INTERFACE
        vpn_ep = next((ep for ep in session.endpoints if ep["address"] == "10.215.173.1"), None)
        self.assertIsNotNone(vpn_ep)
        self.assertEqual(vpn_ep["role"], "VPN_INTERFACE")
        self.assertEqual(vpn_ep["tier"], 1)
        self.assertIn("participant_count", vpn_ep["excluded_from"])
        
        # Excluded from session participant attributes
        self.assertNotEqual(session.participant_private_ip, "10.215.173.1")
        self.assertNotEqual(session.participant_private_ip, "10.215.173.2")
        self.assertNotEqual(session.caller.ip, "10.215.173.1")


if __name__ == "__main__":
    unittest.main()
