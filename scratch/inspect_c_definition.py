import pathlib
import re

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

# Search for the component containing the Gh call
# Let's search around "hosts:c?.rows"
idx = content.find('hosts:c?.rows')
if idx != -1:
    # Let's look back from idx to find the start of the React component (usually a function or hook)
    segment = content[max(0, idx - 5000) : idx]
    # Let's print out how state variables and websocket handlers are defined
    # Look for "useState" or "useEffect" or "ws" or "websocket"
    print("Pre-rendering segment:")
    print(content[max(0, idx - 3000) : idx])
