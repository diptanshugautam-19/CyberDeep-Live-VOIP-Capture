import pathlib

orig_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js.orig')
if orig_path.exists():
    content = orig_path.read_text(encoding='utf-8')
    idx = content.find('jsx)(Gh')
    if idx != -1:
        print("Found jsx)(Gh at index:", idx)
        print(content[idx-100:idx+400])
