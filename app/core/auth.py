import secrets
import time
import logging
from fastapi import Header, HTTPException, Depends, Query, status
from app.storage.database import router

logger = logging.getLogger(__name__)

# Out-of-the-box static API key generation
def get_or_create_api_key() -> str:
    try:
        res = router.execute("user_preferences", "SELECT value FROM user_preferences WHERE key = ?", ("api_key",))
        if res:
            return res[0]["value"]
        
        # Generate a new static key
        new_key = secrets.token_hex(20) # 40 chars hex
        router.execute("user_preferences", "INSERT INTO user_preferences (key, value) VALUES (?, ?)", ("api_key", new_key))
        logger.info(f"==================================================")
        logger.info(f"CYBERDEEP BOOTSTRAP: Generated static capture API key:")
        logger.info(f"   Key: {new_key}")
        logger.info(f"==================================================")
        print(f"==================================================")
        print(f"CYBERDEEP BOOTSTRAP: Generated static capture API key:")
        print(f"   Key: {new_key}")
        print(f"==================================================")
        return new_key
    except Exception as e:
        logger.error(f"Error reading/writing API key in user_preferences: {e}")
        # Return fallback key so server starts
        return "cyberdeep-fallback-token-1234"

STATIC_API_KEY = get_or_create_api_key()

def verify_token(authorization: str = Header(None)) -> str:
    """FastAPI dependency to gate endpoints using Bearer token or static key."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required"
        )
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme. Use 'Bearer <token>'"
        )
    
    token = parts[1]
    if token != STATIC_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid capture API key"
        )
    
    return token

def create_ws_ticket() -> str:
    """Create a short-lived single-use ticket for WebSocket authentication."""
    ticket = secrets.token_urlsafe(32)
    # Tickets expire in 30 seconds
    expires_at = int(time.time()) + 30
    
    router.execute(
        "temp_cache", 
        "INSERT INTO temp_cache (key, value, expires_at) VALUES (?, ?, ?)",
        (f"ws_ticket_{ticket}", "valid", expires_at)
    )
    return ticket

def verify_ws_ticket(ticket: str = Query(...)) -> bool:
    """Verify and consume the WebSocket ticket."""
    if not ticket:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="WebSocket ticket required")
    
    now = int(time.time())
    res = router.execute(
        "temp_cache",
        "SELECT value, expires_at FROM temp_cache WHERE key = ?",
        (f"ws_ticket_{ticket}",)
    )
    
    if not res:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid WebSocket ticket")
    
    expires_at = res[0]["expires_at"]
    if now > expires_at:
        # Delete expired
        router.execute("temp_cache", "DELETE FROM temp_cache WHERE key = ?", (f"ws_ticket_{ticket}",))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="WebSocket ticket expired")
    
    # Consume ticket (single-use)
    router.execute("temp_cache", "DELETE FROM temp_cache WHERE key = ?", (f"ws_ticket_{ticket}",))
    return True
