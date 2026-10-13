"""
 
Runs src/normalize.py's normalize_row() (as exercised by normalize_auth_row/
normalize_web_row/normalize_dns_row/normalize_row("firewall"/"endpoint", ...)
in run_normalize.py) against every row already loaded into clean.db's
raw_<source> tables and exports every successfully normalized row into one
chronologically-sorted output.
The unified schema below is a superset of all 5 sources' output fields.
"""
import csv
import duckdb
import argparse
from src.normalize import normalize_row
 
SOURCES = ["auth", "web", "dns", "firewall", "endpoint"]
 
# Superset of every field any source's normalize_row() can return
FIELDNAMES = [
    "time", "source", "source_line",
    "identity", "method", "path", "query", "action", "event_type",
]
 
 
def load_true_quarantine_reasons(quarantine_csv_path: str):
    """quarantine.csv is produced by src/cli.py from the RAW FILE TEXT via
    ingest.py's parse_json_line, before DuckDB ever sees the row - so it
    still has the real invalid_json vs missing_time distinction that gets
    lost once a malformed line becomes an all-NULL row in a DuckDB table.
    Returns {(source, source_line): true_reason}."""
    true_reasons = {}
    try:
        with open(quarantine_csv_path) as f:
            for row in csv.DictReader(f):
                # locator format from cli.py: "{input_dir}/{source}.jsonl:{line_number}"
                locator = row["locator"]
                line_number = int(locator.rsplit(":", 1)[-1])
                true_reasons[(row["source"], line_number)] = row["reason"]
    except FileNotFoundError:
        print(f"WARNING: {quarantine_csv_path} not found - falling back to "
              f"table-derived quarantine reasons, which cannot distinguish "
              f"invalid_json from missing_time. Run `make build` first.")
    return true_reasons
 
 
def export(db_path: str, out_path: str, quarantine_csv_path: str = "quarantine.csv"):
    true_reasons = load_true_quarantine_reasons(quarantine_csv_path)
 
    con = duckdb.connect(db_path)
 
    timeline_rows = []
    quarantine_counts = {}
 
    for source in SOURCES:
        rows = con.execute(f"SELECT * FROM raw_{source}").fetchall()
        columns = [desc[0] for desc in con.description]
 
        normalized_count = 0
        quarantined = {}
 
        for row_tuple in rows:
            row_dict = dict(zip(columns, row_tuple))
            source_line = row_dict.get("source_line")
            result = normalize_row(source, row_dict)
 
            if "quarantine_reason" in result:
                # Prefer the true, raw-text-derived reason from quarantine.csv
                # when available - it distinguishes invalid_json from
                # missing_time, which the DuckDB-table view cannot.
                reason = true_reasons.get((source, source_line), result["quarantine_reason"])
                quarantined[reason] = quarantined.get(reason, 0) + 1
                continue
 
            normalized_count += 1
            timeline_rows.append({
                "time": result.get("time"),
                "source": source,
                "source_line": source_line,
                "identity": result.get("identity", ""),
                "method": result.get("method", ""),
                "path": result.get("path", ""),
                "query": result.get("query", ""),
                "action": result.get("action", ""),
                "event_type": result.get("event_type", ""),
            })
 
        quarantine_counts[source] = quarantined
        print(f"{source}: normalized={normalized_count} quarantined={sum(quarantined.values())} {quarantined}")
 
    # Sort into an actual timeline: chronological order across all 5 sources.
    timeline_rows.sort(key=lambda r: r["time"])
 
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(timeline_rows)
 
    print(f"\nWrote {len(timeline_rows)} normalized rows to {out_path}")
    con.close()
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="clean.db")
    parser.add_argument("--out", default="normalized-timeline.csv")
    parser.add_argument("--quarantine", default="quarantine.csv",
                         help="Path to quarantine.csv (from `make build`), used to recover the true invalid_json vs missing_time distinction")
    args = parser.parse_args()
    export(args.db, args.out, args.quarantine)
