-- Campaign 1: explicit check that laptop-301 has ZERO auth records
-- anywhere in the archive, in any schema version, top-level or nested.
-- This is the direct evidence backing the rejected hypothesis in
-- campaign-graph.json ("no auth record of any kind exists for
-- laptop-301") and evidence-index.csv C-103.

SELECT COUNT(*) AS auth_rows_mentioning_laptop301
FROM raw_auth
WHERE host = 'laptop-301'
   OR device = 'laptop-301'
   OR record.host = 'laptop-301';
-- Expected and actual: 0

-- nora.contractor's only login that day, for side-by-side comparison
-- against the laptop-301 USB-copy event timestamp. Backs C-101/C-102.
SELECT source_line, COALESCE(timestamp, event_time, time) AS event_time,
       COALESCE(username, identity, record.username) AS identity,
       COALESCE(host, device, record.host) AS host
FROM raw_auth
WHERE COALESCE(username, identity, record.username) = 'nora.contractor'
ORDER BY COALESCE(timestamp, event_time, time);
