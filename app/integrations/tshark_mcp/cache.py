import os
import hashlib
import json
from pathlib import Path
from typing import Dict, Any, Optional

CACHE_DIR = Path("data") / "mcp_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

class McpCache:
    @staticmethod
    def get_file_hash(file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    @classmethod
    def get(cls, file_path: str, query_key: str) -> Optional[Dict[str, Any]]:
        try:
            file_hash = cls.get_file_hash(file_path)
            cache_file = CACHE_DIR / f"{file_hash}_{hashlib.md5(query_key.encode()).hexdigest()}.json"
            if cache_file.exists():
                with open(cache_file, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    @classmethod
    def set(cls, file_path: str, query_key: str, data: Dict[str, Any]):
        try:
            file_hash = cls.get_file_hash(file_path)
            cache_file = CACHE_DIR / f"{file_hash}_{hashlib.md5(query_key.encode()).hexdigest()}.json"
            with open(cache_file, "w") as f:
                json.dump(data, f)
        except Exception:
            pass
