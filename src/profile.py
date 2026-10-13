import duckdb

def profile_source(con, name: str, path: str):
    con.execute(f"""
        CREATE OR REPLACE TABLE raw_{name} AS
        SELECT *
        FROM read_json_auto('{path}', format='newline_delimited', ignore_errors=true)
    """)

    row_count = con.execute(f"SELECT COUNT(*) FROM raw_{name}").fetchone()[0]
    print(f"{name} rows loaded: {row_count}")

    columns = con.execute(f"DESCRIBE raw_{name}").fetchdf()
    print(f"{name} columns:")
    print(columns)


con = duckdb.connect("clean.db")

profile_source(con, "auth", "source/auth.jsonl")
profile_source(con, "web", "source/web.jsonl")
profile_source(con, "dns", "source/dns.jsonl")
profile_source(con, "firewall", "source/firewall.jsonl")
profile_source(con, "endpoint", "source/endpoint.jsonl")
