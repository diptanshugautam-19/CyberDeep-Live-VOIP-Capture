import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

target = 'let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"Not Observable",o_list=[...r];'
replacement = 'let pVal=pIp||"Not Observable",r=n.filter(e=>e&&e.destination_ip&&e.destination_ip!==pPvt).slice(0,4),o_list=[...r];'

if target in content:
    content = content.replace(target, replacement)
    file_path.write_text(content, encoding='utf-8')
    print("Success: Patched frontend hosts filter in bundle.")
else:
    print("Error: Target not found.")
