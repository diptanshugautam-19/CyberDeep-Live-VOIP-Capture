import difflib
import pathlib

file_orig = pathlib.Path('app/static/assets/index-CgfIjOhe.js.orig').read_text(encoding='utf-8')
file_curr = pathlib.Path('app/static/assets/index-CgfIjOhe.js').read_text(encoding='utf-8')

# Let's find differences
# Since they are on one line, we can search around target locations and show the changes
for keyword in ['Gh', '182.74.55.10', 'PARTICIPANT IP']:
    idx_orig = file_orig.find(keyword)
    idx_curr = file_curr.find(keyword)
    if idx_orig != -1 and idx_curr != -1:
        print(f"=== Keyword: {keyword} ===")
        print("ORIGINAL:")
        print(file_orig[max(0, idx_orig - 100) : idx_orig + 400])
        print("CURRENT:")
        print(file_curr[max(0, idx_curr - 100) : idx_curr + 400])
        print("--------------------")
