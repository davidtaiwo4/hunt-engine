-- src/hunt.py: find_external_destinations(con, internal_prefixes)
-- Ranks every external firewall destination IP address by total bytes transferred.
-- internal_prefixes default ranges (10., 172.16., 192.168.) 
--
-- This is what isolated gateway 10.41.50.22 -> 203.0.113.147:443
-- (884,944 bytes, campaign 2) as the only non-recurring outlier among
-- 103 external destinations - the other 102 rows are routine, recurring,
-- scheduled traffic with regular multi-day first_seen/last_seen spans.

SELECT dst_ip,
       COALESCE(src_ip, client_ip, record.src_ip) AS source_ip,
       COUNT(*) AS connections,
       SUM(bytes_out) AS total_bytes,
       MAX(bytes_out) AS max_single_transfer,
       MIN(COALESCE(timestamp, event_time, time)) AS first_seen,
       MAX(COALESCE(timestamp, event_time, time)) AS last_seen
FROM raw_firewall
WHERE dst_ip NOT LIKE '10.%'
  AND dst_ip NOT LIKE '172.16.%'
  AND dst_ip NOT LIKE '192.168.%'
GROUP BY dst_ip, source_ip
ORDER BY total_bytes DESC;

