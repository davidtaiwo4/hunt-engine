import duckdb
from src.normalize import normalize_auth_row

con = duckdb.connect("clean.db")

rows = con.execute("SELECT * FROM raw_auth").fetchall()
columns = [desc[0] for desc in con.description]

normalized = []
quarantined = []

for row_tuple in rows:
    row_dict = dict(zip(columns, row_tuple))
    result = normalize_auth_row(row_dict)

    if "quarantine_reason" in result:
        quarantined.append(result)
    else:
        normalized.append(result)

print(f"normalized: {len(normalized)}")
print(f"quarantined: {len(quarantined)}")
print("sample normalized row:", normalized[0])

from collections import Counter

reasons = Counter(q["quarantine_reason"] for q in quarantined)
print("quarantine reasons breakdown:", dict(reasons))

#run_normalize_web, dns,firewall and endpoint
import duckdb
from collections import Counter
from src.normalize import normalize_web_row, normalize_row

con = duckdb.connect("clean.db")

rows = con.execute("SELECT * FROM raw_web").fetchall()
columns = [desc[0] for desc in con.description]

normalized = []
quarantined = []

for row_tuple in rows:
    row_dict = dict(zip(columns, row_tuple))
    result = normalize_web_row(row_dict)

    if "quarantine_reason" in result:
        quarantined.append(result)
    else:
        normalized.append(result)

print(f"normalized: {len(normalized)}")
print(f"quarantined: {len(quarantined)}")
print("sample normalized row:", normalized[0])

reasons = Counter(q["quarantine_reason"] for q in quarantined)
print("quarantine reasons breakdown:", dict(reasons))

rows = con.execute("SELECT * FROM raw_dns").fetchall()
columns = [desc[0] for desc in con.description]

normalized = []
quarantined = []

for row_tuple in rows:
    row_dict = dict(zip(columns, row_tuple))
    result = normalize_row("dns", row_dict)
    if "quarantine_reason" in result:
        quarantined.append(result)
    else:
        normalized.append(result)

print(f"dns normalized: {len(normalized)}")
print(f"dns quarantined: {len(quarantined)}")
print("sample dns row:", normalized[0])

reasons = Counter(q["quarantine_reason"] for q in quarantined)
print("dns quarantine reasons breakdown:", dict(reasons))

rows = con.execute("SELECT * FROM raw_firewall").fetchall()
columns = [desc[0] for desc in con.description]

normalized = []
quarantined = []

for row_tuple in rows:
    row_dict = dict(zip(columns, row_tuple))
    result = normalize_row("firewall", row_dict)
    if "quarantine_reason" in result:
        quarantined.append(result)
    else:
        normalized.append(result)

print(f"firewall normalized: {len(normalized)}")
print(f"firewall quarantined: {len(quarantined)}")
print("sample firewall row:", normalized[0])

reasons = Counter(q["quarantine_reason"] for q in quarantined)
print("firewall quarantine reasons breakdown:", dict(reasons))

rows = con.execute("SELECT * FROM raw_endpoint").fetchall()
columns = [desc[0] for desc in con.description]

normalized = []
quarantined = []

for row_tuple in rows:
    row_dict = dict(zip(columns, row_tuple))
    result = normalize_row("endpoint", row_dict)
    if "quarantine_reason" in result:
        quarantined.append(result)
    else:
        normalized.append(result)

print(f"endpoint normalized: {len(normalized)}")
print(f"endpoint quarantined: {len(quarantined)}")
print("sample endpoint row:", normalized[0])

reasons = Counter(q["quarantine_reason"] for q in quarantined)
print("endpoint quarantine reasons breakdown:", dict(reasons))
