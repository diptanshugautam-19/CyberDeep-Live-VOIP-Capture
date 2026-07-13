import pathlib
import re

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

for term in ['ticket', '/api/capture/ticket']:
    for m in re.finditer(re.escape(term), content, re.IGNORECASE):
        pos = m.start()
        print(f"Match for '{term}' at {pos}:")
        print(content[max(0, pos - 150) : pos + 350])
        print("---")
