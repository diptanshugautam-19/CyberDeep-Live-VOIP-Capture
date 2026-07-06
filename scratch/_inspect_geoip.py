import sqlite3
conn = sqlite3.connect('data/geoip.sqlite3')
tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("Tables:", tables)
if 'geoip_lookup' in tables:
    info = conn.execute("PRAGMA table_info(geoip_lookup)").fetchall()
    print("geoip_lookup columns:", info)
    count = conn.execute("SELECT COUNT(*) FROM geoip_lookup").fetchone()[0]
    print("geoip_lookup rows:", count)
if 'endpoints' in tables:
    count = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
    print("endpoints rows:", count)
conn.close()
