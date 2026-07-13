import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

target = 'let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"Not Observable",o_list=[...r];'
print("Target in content:", target in content)
