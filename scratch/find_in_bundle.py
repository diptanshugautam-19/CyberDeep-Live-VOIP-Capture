import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

print("File size:", len(content))

# Look for 'Gh' or 'participantIp'
import re

matches = re.findall(r'function\s+Gh[^{]*\{', content)
print("Gh function definition matches:", matches)

matches_part = re.findall(r'participantIp', content)
print("participantIp occurrences:", len(matches_part))

# Search for some keywords that we know should be there
for kw in ['182.74.55.10', 'Reliance Jio', 'New Delhi', 'PARTICIPANT IP']:
    print(f"Keyword '{kw}' in file:", kw in content)
