import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

# Find all occurrences of participantIp
idx = -1
while True:
    idx = content.find('participantIp', idx + 1)
    if idx == -1:
        break
    print(f"Occurrence of 'participantIp' at {idx}:")
    print(content[max(0, idx - 100) : idx + 300])
