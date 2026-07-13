from pathlib import Path

log_path = Path("data/application.log")
lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
print(f"Total lines in application.log: {len(lines)}")
print("=== Last 100 lines ===")
for line in lines[-100:]:
    print(line)
