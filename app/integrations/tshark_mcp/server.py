import sys
import os
import json
import subprocess
import logging
from typing import Dict, Any, List

TSHARK_PATH = r"D:\Wireshark\tshark.exe" if os.path.exists(r"D:\Wireshark\tshark.exe") else "tshark"

# Set up logging to stderr so it doesn't pollute stdout (which is used for JSON-RPC messages)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stderr)
logger = logging.getLogger("tshark-mcp-server")

def run_tshark(args: List[str]) -> str:
    cmd = [TSHARK_PATH] + args
    logger.info(f"Running command: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"TShark error: {e.stderr}")
        raise RuntimeError(f"TShark failed: {e.stderr}")

def tool_analyze_pcap(pcap_path: str, display_filter: str = None, limit: int = 1000) -> Dict[str, Any]:
    # Runs tshark and outputs json formatted packet summary
    # Use -T json or -T ek or similar, but for custom parser let's extract fields to make it fast
    # E.g. -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.protocols -e frame.len -e _ws.col.Info
    args = [
        "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "_ws.col.Info"
    ]
    if display_filter:
        args += ["-Y", display_filter]
    
    # Restrict limit
    args += ["-c", str(limit)]
    
    output = run_tshark(args)
    packets = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        # Ensure we have enough columns
        while len(parts) < 13:
            parts.append("")
        
        idx = parts[0]
        time_epoch = float(parts[1]) if parts[1] else 0.0
        src_ip = parts[2] or parts[4] or "0.0.0.0"
        dst_ip = parts[3] or parts[5] or "0.0.0.0"
        src_port = int(parts[6] or parts[8]) if (parts[6] or parts[8]) else None
        dst_port = int(parts[7] or parts[9]) if (parts[7] or parts[9]) else None
        protocols = parts[10]
        length = int(parts[11]) if parts[11] else 0
        info = parts[12]
        
        packets.append({
            "id": f"p_{idx}",
            "index": int(idx),
            "timestamp": time_epoch,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            "protocol": protocols.split(":")[-1].upper() if protocols else "UNKNOWN",
            "length": length,
            "summary": info,
            "layers": {"protocols": protocols}
        })
    return {"packets": packets}

def tool_list_sip_calls(pcap_path: str) -> Dict[str, Any]:
    # Extract SIP calls using tshark -z sip,calls
    output = run_tshark(["-r", pcap_path, "-z", "sip,calls"])
    calls = []
    # Parse the text table of SIP calls
    # Format typically:
    # Start Time          End Time            Src IP              Dest IP             Call State          Call ID
    lines = output.splitlines()
    parsing = False
    for line in lines:
        if "Start Time" in line and "Call ID" in line:
            parsing = True
            continue
        if parsing:
            if line.startswith("==================") or not line.strip():
                continue
            parts = [p.strip() for p in line.split("   ") if p.strip()]
            if len(parts) >= 5:
                calls.append({
                    "start_time": parts[0],
                    "end_time": parts[1] if len(parts) > 5 else None,
                    "caller": parts[2] if len(parts) > 5 else parts[1],
                    "callee": parts[3] if len(parts) > 5 else parts[2],
                    "status": parts[4] if len(parts) > 5 else parts[3],
                    "call_id": parts[-1]
                })
    return {"calls": calls}

def tool_list_rtp_streams(pcap_path: str) -> Dict[str, Any]:
    # Extract RTP streams using tshark -z rtp,streams
    output = run_tshark(["-r", pcap_path, "-z", "rtp,streams"])
    streams = []
    lines = output.splitlines()
    parsing = False
    for line in lines:
        if "Src IP" in line and "SSRC" in line:
            parsing = True
            continue
        if parsing:
            if line.startswith("==================") or not line.strip():
                continue
            parts = [p.strip() for p in line.split("  ") if p.strip()]
            if len(parts) >= 7:
                streams.append({
                    "source_ip": parts[0],
                    "source_port": int(parts[1]),
                    "dest_ip": parts[2],
                    "dest_port": int(parts[3]),
                    "ssrc": parts[4],
                    "packet_count": int(parts[5]),
                    "lost_packets": int(parts[6].split("(")[0].strip()) if "(" in parts[6] else int(parts[6]),
                    "jitter": float(parts[7]) if len(parts) > 7 else 0.0
                })
    return {"streams": streams}

def tool_extract_ice_candidates(pcap_path: str) -> Dict[str, Any]:
    # Extracts ICE candidate information from STUN messages
    # STUN attributes like username, mapped address, etc.
    args = [
        "-r", pcap_path,
        "-Y", "stun",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "stun.type",
        "-e", "stun.att.username",
        "-e", "stun.att.ipv4",
        "-e", "stun.att.port"
    ]
    output = run_tshark(args)
    candidates = []
    seen = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        while len(parts) < 6:
            parts.append("")
        src_ip, dst_ip, s_type, username, att_ip, att_port = parts
        if username and (username not in seen):
            seen.add(username)
            candidates.append({
                "username": username,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "mapped_ip": att_ip or src_ip,
                "mapped_port": int(att_port) if att_port else None
            })
    return {"candidates": candidates}

def tool_extract_stun_transactions(pcap_path: str) -> Dict[str, Any]:
    args = [
        "-r", pcap_path,
        "-Y", "stun",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "stun.type",
        "-e", "stun.transaction_id"
    ]
    output = run_tshark(args)
    transactions = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        while len(parts) < 8:
            parts.append("")
        f_num, time_ep, src_ip, dst_ip, src_port, dst_port, s_type, t_id = parts
        transactions.append({
            "packet_index": int(f_num) if f_num else 0,
            "timestamp": float(time_ep) if time_ep else 0.0,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": int(src_port) if src_port else 0,
            "dest_port": int(dst_port) if dst_port else 0,
            "type": s_type,
            "transaction_id": t_id
        })
    return {"transactions": transactions}

def tool_summarize_capture(pcap_path: str) -> Dict[str, Any]:
    # Protocol hierarchy statistics
    output = run_tshark(["-r", pcap_path, "-z", "io,phs"])
    return {"summary": output}

def tool_search_packets(pcap_path: str, query: str, limit: int = 1000) -> Dict[str, Any]:
    return tool_analyze_pcap(pcap_path, display_filter=query, limit=limit)

def tool_find_turn_servers(pcap_path: str) -> Dict[str, Any]:
    # Find potential TURN allocation traffic (STUN Allocate messages, etc.)
    # STUN Allocate Request: 0x0003, Allocate Response: 0x0103
    args = [
        "-r", pcap_path,
        "-Y", "stun.type == 0x0003 or stun.type == 0x0103",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "stun.type"
    ]
    output = run_tshark(args)
    servers = []
    seen = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")
        src_ip, dst_ip, src_port, dst_port, s_type = parts
        server_ip = dst_ip if s_type == "0x0003" else src_ip
        server_port = int(dst_port) if s_type == "0x0003" else int(src_port)
        key = f"{server_ip}:{server_port}"
        if key not in seen:
            seen.add(key)
            servers.append({
                "ip": server_ip,
                "port": server_port,
                "type": "TURN_SERVER"
            })
    return {"turn_servers": servers}

TOOLS = {
    "analyze_pcap": tool_analyze_pcap,
    "list_sip_calls": tool_list_sip_calls,
    "list_rtp_streams": tool_list_rtp_streams,
    "extract_ice_candidates": tool_extract_ice_candidates,
    "extract_stun_transactions": tool_extract_stun_transactions,
    "summarize_capture": tool_summarize_capture,
    "search_packets": tool_search_packets,
    "find_turn_servers": tool_find_turn_servers
}

def main():
    logger.info("TShark MCP Server starting...")
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")
            
            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "tshark-mcp-server",
                            "version": "1.0"
                        }
                    }
                }
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                tools_list = []
                for name, func in TOOLS.items():
                    tools_list.append({
                        "name": name,
                        "description": func.__doc__ or f"Execute {name}",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "pcap_path": {"type": "string"},
                                "display_filter": {"type": "string"},
                                "query": {"type": "string"},
                                "limit": {"type": "integer"}
                            },
                            "required": ["pcap_path"]
                        }
                    })
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": tools_list
                    }
                }
            elif method == "tools/call":
                params = req.get("params", {})
                tool_name = params.get("name")
                args = params.get("arguments", {})
                
                if tool_name in TOOLS:
                    try:
                        res = TOOLS[tool_name](**args)
                        resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "result": {
                                "content": [
                                    {"type": "text", "text": json.dumps(res)}
                                ]
                            }
                        }
                    except Exception as e:
                        resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32603,
                                "message": str(e)
                            }
                        }
                else:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32601,
                            "message": f"Tool {tool_name} not found"
                        }
                    }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method {method} not found"
                    }
                }
            
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            logger.error(f"Error handling request: {e}")

if __name__ == "__main__":
    main()
