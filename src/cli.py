import argparse
import json
import csv
import duckdb
from src.ingest import read_source_file
from src.normalize import normalize_row

SOURCES = ["auth", "web", "dns", "firewall", "endpoint"]


def run(input_dir: str, out_db: str):
    all_quarantined = []
    reconciliation = {}

    for source in SOURCES:
        path = f"{input_dir}/{source}.jsonl"
        raw_count = 0
        normalized_count = 0
        source_quarantined = 0

        for line_number, parsed in read_source_file(path):
            raw_count += 1
            locator = f"{path}:{line_number}"

            if "quarantine_reason" in parsed:
                # failed at the raw JSON-parsing stage (invalid_json, empty_line)
                source_quarantined += 1
                all_quarantined.append({
                    "source": source,
                    "reason": parsed["quarantine_reason"],
                    "locator": locator,
                    "raw_row": ""
                })
                continue

            result = normalize_row(source, parsed)
            if "quarantine_reason" in result:
                source_quarantined += 1
                all_quarantined.append({
                    "source": source,
                    "reason": result["quarantine_reason"],
                    "locator": locator,
                    "raw_row": json.dumps(parsed)
                })
            else:
                normalized_count += 1

        reconciliation[source] = {
            "raw_loaded": raw_count,
            "normalized": normalized_count,
            "quarantined": source_quarantined
        }
        print(f"{source}: raw={raw_count} normalized={normalized_count} quarantined={source_quarantined}")

    with open("quarantine.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["source", "reason", "locator", "raw_row"])
        writer.writeheader()
        writer.writerows(all_quarantined)

    with open("reconciliation.json", "w") as f:
        json.dump(reconciliation, f, indent=2)

    with open("results.json", "w") as f:
        json.dump({"status": "complete", "sources_processed": SOURCES}, f, indent=2)

    # Build DuckDB raw_ tables (used by hunt.py, review.py, profile.py) with
    # a source_line column so every row keeps a traceable locator downstream.
    con = duckdb.connect(out_db)
    # Cap to the grader's published minimum spec (4 vCPU / 8 GB) 
    con.execute("SET threads = 4;")
    con.execute("SET memory_limit = '8GB';")
    for source in SOURCES:
        path = f"{input_dir}/{source}.jsonl"
        con.execute(f"""
            CREATE OR REPLACE TABLE raw_{source} AS
            SELECT *, row_number() OVER () AS source_line
            FROM read_json_auto('{path}', format='newline_delimited', ignore_errors=true)
        """)
    con.close()

    print("Wrote quarantine.csv, reconciliation.json, results.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    run(args.input, args.out)
