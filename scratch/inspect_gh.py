import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
if file_path.exists():
    content = file_path.read_text(encoding='utf-8')
    idx = content.find('let n=e.destination_ip,r=n.startsWith')
    if idx != -1:
        print("Found Gh host mapping at index:", idx)
        print(content[idx:idx+1500])
    else:
        print("Not found")
else:
    print("Bundle file does not exist")
