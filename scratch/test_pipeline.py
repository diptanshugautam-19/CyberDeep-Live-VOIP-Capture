import sys
import os
import time
import asyncio
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.core.pipeline import packet_pipeline_handler
from app.core.bridge import broadcast_manager
from app.core.flow_engine import flow_engine
from app.core.enrichment import enrichment_engine
from app.storage.database import init_db

async def simulate_packets(count=500000):
    print(f"Simulating {count} packets rapidly to test pipeline and memory caps...")
    
    start_time = time.time()
    
    for i in range(count):
        # Generate mock packet data
        mock_packet = {
            "source_ip": f"10.0.0.{i % 255}",
            "destination_ip": "192.168.1.100",
            "source_port": 10000 + (i % 1000),
            "destination_port": 80,
            "protocol": "TCP",
            "length": 64 + (i % 1000),
            "timestamp": time.time(),
            "summary": f"Mock packet {i}",
            "tcp_flags": "S",
            "tcp_state": "SYN_SENT",
            "payload_preview": ""
        }
        
        # Inject directly into the pipeline handler
        packet_pipeline_handler(mock_packet)
        
        if i % 50000 == 0:
            print(f"Processed {i} packets...")
            # Yield to event loop to allow enrichment/flows to catch up
            await asyncio.sleep(0.01)

    end_time = time.time()
    print(f"Finished {count} packets in {end_time - start_time:.2f} seconds.")
    print(f"Rate: {count / (end_time - start_time):.2f} packets/sec")

async def main():
    print("Initializing databases...")
    init_db()
    
    print("Starting background engines...")
    flow_engine.start()
    enrichment_engine.start()
    
    # Run simulation
    await simulate_packets(500000)
    
    # Let engines finish queues
    print("Waiting for queues to drain...")
    await asyncio.sleep(2)
    
    print("Shutting down...")
    flow_engine.stop()
    await enrichment_engine.stop()
    print("Test Complete.")

if __name__ == "__main__":
    asyncio.run(main())
