-- src/hunt.py: find_unattributed_activity(con, entity_field_expr, entity_table,
-- lookup_table, window_hours)
-- Given an activity table and an entity (host/IP) expression, checks
-- whether any auth session in lookup_table covers a window_hours window
-- around each activity's timestamp. Returns activities with NO covering
-- session. Generalized across any table/entity field 
--
-- This is the shape it takes when entity_field_expr=dst_ip,
-- entity_table=raw_firewall, window_hours=2.

WITH activity AS (
    SELECT dst_ip AS entity,
           COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_firewall
    WHERE dst_ip IS NOT NULL
)
SELECT a.entity, a.event_time
FROM activity a
WHERE NOT EXISTS (
    SELECT 1 FROM raw_auth l
    WHERE COALESCE(l.src_ip, l.client_ip, l.record.src_ip) = a.entity
      AND COALESCE(l.timestamp, l.event_time, l.time)
          BETWEEN a.event_time - INTERVAL '2 hours'
              AND a.event_time + INTERVAL '2 hours'
)
ORDER BY a.event_time;
