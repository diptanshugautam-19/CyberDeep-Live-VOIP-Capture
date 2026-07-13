class TSharkMcpError(Exception):
    """Base exception for all TShark MCP integration errors."""
    pass

class TSharkNotFoundError(TSharkMcpError):
    """Raised when tshark executable cannot be found."""
    pass

class PCAPParseError(TSharkMcpError):
    """Raised when tshark fails to parse the PCAP file."""
    pass

class MCPTimeoutError(TSharkMcpError):
    """Raised when an MCP request/response times out."""
    pass

class MCPServerError(TSharkMcpError):
    """Raised when the MCP server returns an error code."""
    pass
