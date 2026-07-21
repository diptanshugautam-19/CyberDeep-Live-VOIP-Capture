import html.parser
import sys

class HTMLTestParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.errors = []
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, self.getpos()))

    def handle_endtag(self, tag):
        if not self.tags:
            self.errors.append(f"Unexpected end tag </{tag}> at line {self.getpos()[0]}")
            return
        last_tag, pos = self.tags.pop()
        if last_tag != tag:
            self.errors.append(f"Mismatched tags: <{last_tag}> at line {pos[0]} closed by </{tag}> at line {self.getpos()[0]}")

with open("app/templates/unified.html", "r", encoding="utf-8") as f:
    content = f.read()

parser = HTMLTestParser()
try:
    parser.feed(content)
except Exception as e:
    print(f"Parser exception: {e}")
    sys.exit(1)

if parser.errors:
    print("Found HTML issues:")
    for err in parser.errors:
        print(" -", err)
else:
    print("No mismatched tags or HTML syntax issues found.")
