# Usage Documentation

## Analyze Evidence

1. Start the server with `uvicorn app.main:app --reload`.
2. Open `http://127.0.0.1:8000`.
3. Upload one or more `.pcap`, `.pcapng`, `.csv`, `.tsv`, `.log`, or `.txt` evidence files.
4. Review the dashboard cards, communication graph, map, charts, and destination table.
4. Review the destination table, evidence correlation, attribution report, and right-side investigation workspace.

## Supported CSV Columns

The parser recognizes common Wireshark, NetFlow, and firewall-style aliases:

- Source IP: `source_ip`, `src_ip`, `src`, `ip.src`, `source address`
- Destination IP: `destination_ip`, `dst_ip`, `dest_ip`, `ip.dst`, `destination address`
- Ports: `source_port`, `src_port`, `destination_port`, `dst_port`, `tcp.dstport`, `udp.dstport`
- Protocol: `protocol`, `_ws.col.protocol`, `proto`
- Timestamp: `timestamp`, `time`, `_ws.col.time`, `frame.time`, `first_seen`
- Volume: `bytes`, `octets`, `frame.len`, `packet_count`, `packets`, `frames`

## Filtering

Use the left-side controls to filter by IP, ASN, telecom provider, country, service, threat level, and destination port.

## Exports

After analysis, the export buttons generate:

- PDF forensic summary
- Excel workbook
- CSV destination table
- JSON investigation bundle

## Live Intelligence Source Labels

When online enrichment is enabled, the investigation drawer will show the source of IP intelligence, for example:

- `IPinfo live`
- `Local GeoIP`

## Extending Threat Intelligence

Create a class that extends `ThreatFeed`:

```python
from app.threat_intel.base import ThreatFeed

class MyFeed(ThreatFeed):
    name = "My Feed"

    def lookup(self, ip: str) -> dict:
        return {
            "feed": self.name,
            "reputation_score": 0,
            "malicious": False,
            "threat_category": "None",
            "last_reported": "",
        }
```

Register it in `app/threat_intel/manager.py`.
