import duckdb
from src.hunt import (
    find_rare_field_values, find_external_destinations,
    find_login_spray_pattern, find_correlation_tagged_events, get_events_for_tag
)

con = duckdb.connect("clean.db")
# To use the grader's published minimum spec (4 vCPU / 8 GB).
con.execute("SET threads = 4;")
con.execute("SET memory_limit = '8GB';")

print("=== Rare endpoint event types (max 3 occurrences) ===")
print(find_rare_field_values(con, "raw_endpoint", "COALESCE(event, event_name, record.event)", max_occurrences=3))

print("\n=== External firewall destinations, ranked by bytes ===")
print(find_external_destinations(con))

print("\n=== Login spray candidates (5+ distinct days of failures) ===")
print(find_login_spray_pattern(con, min_distinct_days=5))

print("\n=== Correlation-tagged events (any campaign the data self-labels) ===")
tags = find_correlation_tagged_events(con)
print(tags)

for tag_value in tags["correlation_id"].tolist():
    print(f"\n=== Full timeline for correlation_id={tag_value} ===")
    print(get_events_for_tag(con, "correlation_id", tag_value))
