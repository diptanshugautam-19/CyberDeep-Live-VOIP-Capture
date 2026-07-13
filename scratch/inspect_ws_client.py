import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

import re
for term in ['WebSocket', 'ws://', 'wss://', '/ws', 'onmessage', 'socket']:
    for m in re.finditer(re.escape(term), content, re.IGNORECASE):
        pos = m.start()
        print(f"Match for '{term}' at {pos}:")
        print(content[max(0, pos - 150) : pos + 350])
        print("---")
