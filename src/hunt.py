"""
Reusable threat hunting functions. Every function takes explicit parameters
(thresholds, field lists, prefixes) to search for suspicious activities.
"""
import duckdb


def resolve_host(alias: str = "") -> str:
    """SQL fragment resolving a host name across all 3 schema-version
    field-naming conventions found during profiling (v1: host, v2: device,
    v3: nested record.host)."""
    p = f"{alias}." if alias else ""
    return f"COALESCE({p}host, {p}device, {p}record.host)"
 
 
def resolve_identity(alias: str = "", v1_field: str = "username", v2_field: str = "identity") -> str:
    """SQL fragment resolving an identity field across schema versions.
    v1_field/v2_field are parameters because different sources use
    different field names (e.g. auth: username/identity, endpoint: user/identity)."""
    p = f"{alias}." if alias else ""
    return f"COALESCE({p}{v1_field}, {p}{v2_field}, {p}record.{v1_field})"
 
 
def resolve_ip(alias: str = "", v1_field: str = "src_ip", v2_field: str = "client_ip") -> str:
    p = f"{alias}." if alias else ""
    return f"COALESCE({p}{v1_field}, {p}{v2_field}, {p}record.{v1_field})"
 
 
def find_rare_field_values(con, table: str, field_expr: str, max_occurrences: int = 3):
    """Generic rarity scan. Returns values of field_expr in table occurring
    at most max_occurrences times. Works on any table/column combination -
    the caller decides what field to scan, not this function."""
    return con.execute(f"""
        SELECT {field_expr} AS value, COUNT(*) AS occurrences
        FROM {table}
        WHERE {field_expr} IS NOT NULL
        GROUP BY {field_expr}
        HAVING COUNT(*) <= {max_occurrences}
        ORDER BY occurrences ASC
    """).fetchdf()
 
 
def find_external_destinations(con, internal_prefixes: list = None):
    """Ranks firewall destinations by total bytes transferred, restricted
    to IPs that do NOT match any given internal prefix. internal_prefixes
    is a parameter (default RFC1918 ranges) - not hardcoded per-dataset,
    so this generalizes to any addressing scheme."""
    if internal_prefixes is None:
        internal_prefixes = ["10.", "172.16.", "192.168."]
    conditions = " AND ".join(f"dst_ip NOT LIKE '{p}%'" for p in internal_prefixes)
    return con.execute(f"""
        SELECT dst_ip,
               {resolve_ip()} AS source_ip,
               COUNT(*) AS connections,
               SUM(bytes_out) AS total_bytes,
               MAX(bytes_out) AS max_single_transfer,
               MIN(COALESCE(timestamp, event_time, time)) AS first_seen,
               MAX(COALESCE(timestamp, event_time, time)) AS last_seen
        FROM raw_firewall
        WHERE {conditions}
        GROUP BY dst_ip, source_ip
        ORDER BY total_bytes DESC
    """).fetchdf()
 
 
def find_login_spray_pattern(con, min_distinct_days: int = 5, failure_values: list = None):
    """Detects source-IP/target-host pairs with failed login attempts
    spread across at least min_distinct_days distinct calendar days - the
    low-and-slow spray signature - without hardcoding which IP, host, or
    date range to look for. min_distinct_days is the only tunable knob."""
    if failure_values is None:
        failure_values = ["login_failed"]
    values_list = ", ".join(f"'{v}'" for v in failure_values)
    return con.execute(f"""
        WITH failed AS (
            SELECT
                {resolve_ip()} AS source_ip,
                {resolve_host()} AS target_host,
                CAST(COALESCE(timestamp, event_time, time) AS DATE) AS day,
                COALESCE(timestamp, event_time, time) AS event_time
            FROM raw_auth
            WHERE COALESCE(action, result, record.action) IN ({values_list})
        )
        SELECT source_ip, target_host,
               COUNT(DISTINCT day) AS distinct_days,
               COUNT(*) AS total_attempts,
               MIN(event_time) AS first_attempt,
               MAX(event_time) AS last_attempt
        FROM failed
        WHERE source_ip IS NOT NULL AND target_host IS NOT NULL
        GROUP BY source_ip, target_host
        HAVING COUNT(DISTINCT day) >= {min_distinct_days}
        ORDER BY distinct_days DESC
    """).fetchdf()
 
 
def find_correlation_tagged_events(con, sources: list = None):
    """Finds every distinct correlation_id value across the given sources
    and how many events/sources carry each tag. This is the generic
    mechanism (not a hardcoded 'spray-v1' lookup) that surfaces any
    campaign the data itself has tagged, on any archive.
 
    Queries each source independently (rather than one UNION ALL) because
    DuckDB infers a STRUCT type per source's `record` column from that
    source's own JSON. If a source never has correlation_id nested under
    record at all (not just NULL - genuinely absent from every row DuckDB
    sampled), referencing record.correlation_id against that source raises
    a BinderException: 'Could not find key "correlation_id" in struct'.
    A single UNION ALL query fails as soon as any one source lacks the
    field; per-source try/except lets the sources that do have it succeed
    and simply skips the ones that don't."""
    if sources is None:
        sources = ["auth", "web", "dns", "firewall", "endpoint"]
    import pandas as pd
    frames = []
    for s in sources:
        try:
            df = con.execute(f"""
                SELECT '{s}' AS source, record.correlation_id AS correlation_id
                FROM raw_{s}
                WHERE record.correlation_id IS NOT NULL
            """).fetchdf()
        except duckdb.BinderException:
            # This source's record struct has no correlation_id key at all.
            continue
        if len(df) > 0:
            frames.append(df)
    if not frames:
        return pd.DataFrame(columns=["correlation_id", "source_count", "event_count"])
    combined = pd.concat(frames, ignore_index=True)
    return (
        combined.groupby("correlation_id")
        .agg(source_count=("source", "nunique"), event_count=("source", "size"))
        .reset_index()
        .sort_values(["source_count", "event_count"], ascending=False)
        .reset_index(drop=True)
    )
 
 
def get_events_for_tag(con, tag_field: str, tag_value: str, sources: list = None):
    """Pulls every raw row where tag_field = tag_value across all given
    sources, in time order. tag_value is supplied by the caller (e.g. from
    find_correlation_tagged_events results) - never hardcoded here.
 
    Each source is queried in its own try/except: a source whose record
    struct never contains tag_field at all raises a BinderException on
    record.{tag_field}, which is expected (not every source is guaranteed
    to carry every tag) and is skipped rather than aborting the whole call."""
    if sources is None:
        sources = ["auth", "web", "dns", "firewall", "endpoint"]
    frames = []
    for s in sources:
        try:
            df = con.execute(f"""
                SELECT '{s}' AS source, *
                FROM raw_{s}
                WHERE record.{tag_field} = ?
            """, [tag_value]).fetchdf()
        except duckdb.BinderException:
            continue
        if len(df) > 0:
            frames.append(df)
    if not frames:
        return None
    import pandas as pd
    return pd.concat(frames, ignore_index=True, sort=False)
 
 
def find_unattributed_activity(con, entity_field_expr: str, entity_table: str,
                                lookup_table: str = "raw_auth", window_hours: int = 2):
    """Given an activity table and an entity (host/IP) expression, checks
    whether any auth session in lookup_table covers a window_hours window
    around each activity's timestamp. Returns activities with NO covering
    session - i.e. unattributed activity - generalized across any table
    and entity field, not one specific IP or host."""
    return con.execute(f"""
        WITH activity AS (
            SELECT {entity_field_expr} AS entity,
                   COALESCE(timestamp, event_time, time) AS event_time
            FROM {entity_table}
            WHERE {entity_field_expr} IS NOT NULL
        )
        SELECT a.entity, a.event_time
        FROM activity a
        WHERE NOT EXISTS (
            SELECT 1 FROM {lookup_table} l
            WHERE {resolve_ip("l")} = a.entity
              AND COALESCE(l.timestamp, l.event_time, l.time)
                  BETWEEN a.event_time - INTERVAL '{window_hours} hours'
                      AND a.event_time + INTERVAL '{window_hours} hours'
        )
        ORDER BY a.event_time
    """).fetchdf()
