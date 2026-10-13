import duckdb

con = duckdb.connect("clean.db")

result = con.execute("""
    WITH host_ip_map AS (
        SELECT DISTINCT host, src_ip
        FROM raw_auth
        WHERE host IS NOT NULL AND src_ip IS NOT NULL
    ),
    auth_events AS (
        SELECT host AS actor_host, action AS detail, COALESCE(timestamp, event_time, time) AS event_time
        FROM raw_auth WHERE host IS NOT NULL
    ),
    firewall_events AS (
        SELECT m.host AS actor_host, COALESCE(f.action, f.result) AS detail, COALESCE(f.timestamp, f.event_time, f.time) AS event_time
        FROM raw_firewall f JOIN host_ip_map m ON f.src_ip = m.src_ip
    ),
    endpoint_events AS (
        SELECT host AS actor_host, COALESCE(event, event_name) AS detail, COALESCE(timestamp, event_time, time) AS event_time
        FROM raw_endpoint WHERE host IS NOT NULL
    ),
    combined AS (
        SELECT * FROM auth_events
        UNION ALL SELECT * FROM firewall_events
        UNION ALL SELECT * FROM endpoint_events
    )
    SELECT actor_host, detail, COUNT(*) AS occurrences
    FROM combined
    WHERE detail IS NOT NULL
    GROUP BY actor_host, detail
    ORDER BY occurrences ASC
    LIMIT 30
""").fetchdf()

print(result)

rare_actions = con.execute("""
    SELECT detail, COUNT(*) AS occurrences
    FROM (
        SELECT action AS detail FROM raw_auth
        UNION ALL SELECT COALESCE(action, result) FROM raw_firewall
        UNION ALL SELECT COALESCE(event, event_name) FROM raw_endpoint
    )
    WHERE detail IS NOT NULL
    GROUP BY detail
    ORDER BY occurrences ASC
    LIMIT 30
""").fetchdf()

print(rare_actions)

rare_events = con.execute("""
    SELECT
        schema_version,
        host,
        COALESCE(event, event_name) AS event_type,
        COALESCE(timestamp, event_time, time) AS event_time,
        user,
        image,
        command_line,
        parent,
        destination
    FROM raw_endpoint
    WHERE COALESCE(event, event_name) IN ('file_copy', 'file_delete')
""").fetchdf()

print("RARE ENDPOINT EVENTS:")
for row in rare_events.to_dict(orient="records"):
    print(row)
    print()

timeline = con.execute("""
    SELECT 'auth' AS source, action AS detail, COALESCE(username, identity) AS who, COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_auth
    WHERE host = 'laptop-301' OR username = 'nora.contractor' OR identity = 'nora.contractor'
    UNION ALL
    SELECT 'endpoint' AS source, COALESCE(event, event_name) AS detail, user AS who, COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_endpoint
    WHERE host = 'laptop-301' OR user = 'nora.contractor'
    ORDER BY event_time
""").fetchdf()

print("TIMELINE FOR laptop-301 / nora.contractor:")
for row in timeline.to_dict(orient="records"):
    print(row)

host_ip = con.execute("""
    SELECT DISTINCT src_ip FROM raw_auth WHERE host = 'laptop-301' AND src_ip IS NOT NULL
""").fetchdf()
print("IP(s) for laptop-301:", host_ip)

remaining_sources = con.execute("""
    SELECT 'web' AS source, COALESCE(method,'') || ' ' || COALESCE(path,'') AS detail, COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_web
    WHERE src_ip IN (SELECT src_ip FROM raw_auth WHERE host = 'laptop-301')
    UNION ALL
    SELECT 'dns' AS source, query AS detail, COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_dns
    WHERE host = 'laptop-301'
    UNION ALL
    SELECT 'firewall' AS source, COALESCE(action, result) || ' -> ' || COALESCE(dst_ip,'') AS detail, COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_firewall
    WHERE src_ip IN (SELECT src_ip FROM raw_auth WHERE host = 'laptop-301')
    ORDER BY event_time
""").fetchdf()

print("WEB/DNS/FIREWALL FOR laptop-301:")
for row in remaining_sources.to_dict(orient="records"):
    print(row)

check = con.execute("""
    SELECT schema_version, src_ip, client_ip, timestamp, event_time
    FROM raw_auth
    WHERE host = 'laptop-301'
""").fetchdf()

print("ALL AUTH ROWS FOR laptop-301:")
for row in check.to_dict(orient="records"):
    print(row)

nora_auth = con.execute("""
    SELECT schema_version, host, src_ip, client_ip, username, identity, action, result, timestamp, event_time
    FROM raw_auth
    WHERE username = 'nora.contractor' OR identity = 'nora.contractor'
""").fetchdf()

print("ALL AUTH ROWS FOR nora.contractor:")
for row in nora_auth.to_dict(orient="records"):
    print(row)

who_used_laptop = con.execute("""
    SELECT schema_version, host, username, identity, action, result, timestamp, event_time
    FROM raw_auth
    WHERE host = 'laptop-301'
       OR src_ip IN (SELECT src_ip FROM raw_auth WHERE username = 'nora.contractor')
""").fetchdf()

print("ANY AUTH ACTIVITY NEAR laptop-301:")
for row in who_used_laptop.to_dict(orient="records"):
    print(row)

archive_events = con.execute("""
    SELECT
        host,
        user,
        COALESCE(timestamp, event_time, time) AS event_time,
        destination
    FROM raw_endpoint
    WHERE COALESCE(event, event_name) = 'archive_create'
    ORDER BY event_time
""").fetchdf()

print(f"total archive_create events: {len(archive_events)}")
print("BY HOST:")
print(archive_events['host'].value_counts())
print()
print("SAMPLE ROWS:")
for row in archive_events.head(15).to_dict(orient="records"):
    print(row)

web_rare = con.execute("""
    SELECT status, COUNT(*) AS occurrences
    FROM raw_web
    WHERE status IS NOT NULL
    GROUP BY status
    ORDER BY occurrences ASC
    LIMIT 10
""").fetchdf()
print("WEB STATUS CODES (rarest first):")
print(web_rare)
print()

web_paths = con.execute("""
    SELECT path, COUNT(*) AS occurrences
    FROM raw_web
    WHERE path IS NOT NULL
    GROUP BY path
    ORDER BY occurrences ASC
    LIMIT 15
""").fetchdf()
print("WEB PATHS (rarest first):")
print(web_paths)
print()

dns_rare = con.execute("""
    SELECT query, COUNT(*) AS occurrences
    FROM raw_dns
    WHERE query IS NOT NULL
    GROUP BY query
    ORDER BY occurrences ASC
    LIMIT 15
""").fetchdf()
print("DNS QUERIES (rarest first):")
print(dns_rare)
print()

firewall_rare = con.execute("""
    SELECT dst_ip, COUNT(*) AS occurrences
    FROM raw_firewall
    WHERE dst_ip IS NOT NULL
    GROUP BY dst_ip
    ORDER BY occurrences ASC
    LIMIT 15
""").fetchdf()
print("FIREWALL DESTINATIONS (rarest first):")
print(firewall_rare)

external_conns = con.execute("""
    SELECT *
    FROM raw_firewall
    WHERE dst_ip IN ('198.51.100.250', '203.0.113.147')
""").fetchdf()

print("EXTERNAL FIREWALL CONNECTIONS:")
for row in external_conns.to_dict(orient="records"):
    print(row)
print()

forbidden_request = con.execute("""
    SELECT *
    FROM raw_web
    WHERE status = 403
""").fetchdf()

print("403 FORBIDDEN REQUEST:")
for row in forbidden_request.to_dict(orient="records"):
    print(row)

all_auth_for_ip = con.execute("""
    SELECT host, username, COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_auth
    WHERE src_ip = '10.41.50.22'
    ORDER BY event_time
""").fetchdf()

print(f"total auth rows ever for 10.41.50.22: {len(all_auth_for_ip)}")
for row in all_auth_for_ip.to_dict(orient="records"):
    print(row)

around_transfer = con.execute("""
    SELECT host, COALESCE(event, event_name) AS detail, user, COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_endpoint
    WHERE host IN ('host-140', 'host-453', 'host-257', 'host-445')
      AND CAST(COALESCE(timestamp, event_time, time) AS DATE) = '2026-06-18'
    ORDER BY event_time
""").fetchdf()

print(f"total endpoint events on these 4 hosts, 2026-06-18: {len(around_transfer)}")
for row in around_transfer.to_dict(orient="records"):
    print(row)

baseline = con.execute("""
    SELECT dst_ip, COUNT(*) AS connections, SUM(bytes_out) AS total_bytes, AVG(bytes_out) AS avg_bytes
    FROM raw_firewall
    WHERE src_ip = '10.41.50.22'
    GROUP BY dst_ip
    ORDER BY total_bytes DESC
    LIMIT 10
""").fetchdf()

print("ALL DESTINATIONS FROM 10.41.50.22, BY VOLUME:")
print(baseline)
#campaign 3 finding
failed_logins = con.execute("""
    SELECT
        COALESCE(host, device, record.host) AS resolved_host,
        COUNT(*) AS fail_count,
        MIN(COALESCE(timestamp, event_time, time)) AS first_fail,
        MAX(COALESCE(timestamp, event_time, time)) AS last_fail
    FROM raw_auth
    WHERE action = 'login_failed' OR result = 'login_failed'
    GROUP BY resolved_host
    ORDER BY fail_count DESC
    LIMIT 15
""").fetchdf()

print("TOP HOSTS BY FAILED LOGIN COUNT (corrected):")
print(failed_logins)
