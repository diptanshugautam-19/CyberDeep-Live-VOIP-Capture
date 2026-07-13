import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

idx = content.find('hosts:c?.rows')
if idx != -1:
    print("c Segment:")
    print(content[max(0, idx - 400) : idx + 400])
