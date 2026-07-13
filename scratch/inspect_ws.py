import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

# Search for WebSocket message handler keywords: "voip_sessions" or "websocket" or "onmessage"
import re
for term in ['voip_sessions', 'voip_update', 'onmessage', 'socket']:
    idx = content.find(term)
    if idx != -1:
        print(f"Match for '{term}':")
        print(content[max(0, idx - 150) : idx + 350])
        print("---")
