-- src/hunt.py: find_rare_field_values(con, table, field_expr, max_occurrences)
-- Rarity scan. Shown here with the actual parameters run_hunt.py
-- passes: table=raw_endpoint, field_expr=COALESCE(event, event_name,
-- record.event), max_occurrences=3. This is what first surfaced the
-- laptop-301 file_copy/removable_media_mount events (campaign 1) as
-- statistical outliers among endpoint event types.

SELECT COALESCE(event, event_name, record.event) AS value, COUNT(*) AS occurrences
FROM raw_endpoint
WHERE COALESCE(event, event_name, record.event) IS NOT NULL
GROUP BY COALESCE(event, event_name, record.event)
HAVING COUNT(*) <= 3
ORDER BY occurrences ASC;
