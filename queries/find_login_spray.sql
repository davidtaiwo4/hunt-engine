-- src/hunt.py: find_login_spray_pattern(con, min_distinct_days, failure_values)
-- Detects source-IP/target-host pairs with failed logins spread across at
-- least min_distinct_days distinct calendar days.
-- Shown here with the actual parameters run_hunt.py passes: min_distinct_days=5,
-- failure_values=['login_failed'].
--
-- This is what surfaced 198.51.100.124 -> vpn-01 (campaign 3) as the only
-- pair in the archive meeting the threshold.

WITH failed AS (
    SELECT
        COALESCE(src_ip, client_ip, record.src_ip) AS source_ip,
        COALESCE(host, device, record.host) AS target_host,
        CAST(COALESCE(timestamp, event_time, time) AS DATE) AS day,
        COALESCE(timestamp, event_time, time) AS event_time
    FROM raw_auth
    WHERE COALESCE(action, result, record.action) IN ('login_failed')
)
SELECT source_ip, target_host,
       COUNT(DISTINCT day) AS distinct_days,
       COUNT(*) AS total_attempts,
       MIN(event_time) AS first_attempt,
       MAX(event_time) AS last_attempt
FROM failed
WHERE source_ip IS NOT NULL AND target_host IS NOT NULL
GROUP BY source_ip, target_host
HAVING COUNT(DISTINCT day) >= 5
ORDER BY distinct_days DESC;

