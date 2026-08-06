import sys
import argparse
from app.analysis.attribution_engine import AttributionEngine, OutputFormatter

def main():
    parser = argparse.ArgumentParser(description="Remote Participant Public IP Attribution Engine CLI")
    parser.add_argument("pcap_path", help="Path to PCAP/PCAPNG file to analyze")
    parser.add_argument("--sdp", help="Optional path to SDP file")
    args = parser.parse_args()
    
    engine = AttributionEngine()
    if args.sdp:
        with open(args.sdp, "r", encoding="utf-8") as f:
            engine.ingest_sdp(f.read())
            
    try:
        from scapy.all import rdpcap, IP, IPv6, UDP, TCP, Raw
        packets = rdpcap(args.pcap_path)
    except Exception as exc:
        print(f"Error loading scapy or PCAP file: {exc}")
        sys.exit(1)
        
    for i, pkt in enumerate(packets):
        src_ip = dst_ip = None
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            
        if not src_ip or not dst_ip:
            continue
            
        src_port = dst_port = None
        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            
        if not src_port or not dst_port:
            continue
            
        payload = bytes(pkt[Raw].load) if Raw in pkt else b""
        timestamp = float(pkt.time)
        
        engine.ingest_packet(payload, src_ip, src_port, dst_ip, dst_port, timestamp)
        
    summary = engine.analyze()
    print("=== ANALYSIS RESULTS ===")
    print(OutputFormatter.format(summary, engine))
    
    evidence = OutputFormatter.format_evidence(summary, engine)
    if evidence:
        print("\n=== EVIDENCE TRAIL ===")
        print(evidence)

if __name__ == "__main__":
    main()
