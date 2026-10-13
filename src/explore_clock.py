import duckdb

con = duckdb.connect("clean.db")

result = con.execute("""
    SELECT
        e.host AS endpoint_host,
        COALESCE(e.timestamp, e.event_time, e.time) AS endpoint_time,
        f.src_ip AS firewall_src_ip,
        COALESCE(f.timestamp, f.event_time, f.time) AS firewall_time,
        ABS(EPOCH(COALESCE(e.timestamp, e.event_time, e.time)) -
            EPOCH(COALESCE(f.timestamp, f.event_time, f.time))) AS seconds_apart
    FROM raw_endpoint e
    JOIN raw_auth a ON e.host = a.host
    JOIN raw_firewall f ON a.src_ip = f.src_ip
    ORDER BY seconds_apart ASC
    LIMIT 10
""").fetchdf()

print(result)

result = con.execute("""
    SELECT
        e.host AS endpoint_host,
        COALESCE(e.event, e.event_name, e.record.event) AS endpoint_event,
        COALESCE(e.timestamp, e.event_time, e.time) AS endpoint_time,
        a.src_ip AS mapped_ip,
        f.src_ip AS firewall_src_ip,
        COALESCE(f.action, f.result, f.record.action) AS firewall_action,
        COALESCE(f.timestamp, f.event_time, f.time) AS firewall_time
    FROM raw_endpoint e
    JOIN raw_auth a
      ON e.host = a.host
    JOIN raw_firewall f
      ON a.src_ip = f.src_ip
    ORDER BY endpoint_time
    LIMIT 20
""").fetchdf()

print(result)
rare_events = con.execute("""
    SELECT *
    FROM raw_endpoint
    WHERE COALESCE(event, event_name) IN ('file_copy', 'file_delete')
""").fetchdf()

print(rare_events)
