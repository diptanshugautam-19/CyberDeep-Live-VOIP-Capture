import sys
import os
import json
import asyncio
import logging
from typing import Dict, Any, Optional
from app.integrations.tshark_mcp.exceptions import MCPServerError, MCPTimeoutError, TSharkNotFoundError

logger = logging.getLogger("tshark-mcp-client")

class TSharkMcpClient:
    def __init__(self):
        self.process: Optional[asyncio.subprocess.Process] = None
        self.msg_id = 0
        self.lock = asyncio.Lock()
        self.server_path = os.path.join(os.path.dirname(__file__), "server.py")

    async def start(self):
        if self.process:
            return
        
        logger.info(f"Starting TShark MCP Server: {self.server_path}")
        
        # Start server.py as a subprocess
        self.process = await asyncio.create_subprocess_exec(
            sys.executable, self.server_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Run initialize
        try:
            init_res = await self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "VoIPWireStreamClient", "version": "1.0"}
            })
            logger.info(f"MCP Server initialized: {init_res}")
            
            # Send initialized notification
            await self._send_notification("notifications/initialized", {})
        except Exception as e:
            logger.error(f"Failed to initialize MCP Server: {e}")
            await self.stop()
            raise

    async def stop(self):
        if self.process:
            try:
                self.process.terminate()
                await self.process.wait()
            except Exception:
                pass
            self.process = None

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 30.0) -> Dict[str, Any]:
        if not self.process:
            await self.start()
        
        async with self.lock:
            self.msg_id += 1
            req_id = self.msg_id
            
            payload = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
            
            req_str = json.dumps(payload) + "\n"
            try:
                self.process.stdin.write(req_str.encode('utf-8'))
                await self.process.stdin.drain()
            except Exception as e:
                logger.error(f"Failed to write to MCP Server stdin: {e}")
                # Try to restart and retry once
                await self.stop()
                await self.start()
                self.process.stdin.write(req_str.encode('utf-8'))
                await self.process.stdin.drain()

            try:
                # Read stdout line by line
                line_task = asyncio.create_task(self.process.stdout.readline())
                done, pending = await asyncio.wait([line_task], timeout=timeout)
                if line_task in done:
                    line = line_task.result()
                    if not line:
                        raise MCPServerError("MCP server connection closed.")
                    
                    resp = json.loads(line.decode('utf-8'))
                    if resp.get("error"):
                        raise MCPServerError(resp["error"].get("message", "Unknown error"))
                    
                    content_list = resp.get("result", {}).get("content", [])
                    if content_list and content_list[0].get("type") == "text":
                        return json.loads(content_list[0]["text"])
                    return resp.get("result", {})
                else:
                    line_task.cancel()
                    raise MCPTimeoutError(f"Tool call {tool_name} timed out after {timeout} seconds.")
            except Exception as e:
                logger.error(f"Error during tool call {tool_name}: {e}")
                raise

    async def _send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.msg_id += 1
        req_id = self.msg_id
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params
        }
        self.process.stdin.write((json.dumps(payload) + "\n").encode('utf-8'))
        await self.process.stdin.drain()
        
        line = await self.process.stdout.readline()
        if not line:
            raise MCPServerError("MCP Server closed connection.")
        resp = json.loads(line.decode('utf-8'))
        if resp.get("error"):
            raise MCPServerError(resp["error"].get("message", "Unknown error"))
        return resp.get("result", {})

    async def _send_notification(self, method: str, params: Dict[str, Any]):
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        self.process.stdin.write((json.dumps(payload) + "\n").encode('utf-8'))
        await self.process.stdin.drain()
