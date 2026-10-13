-- src/hunt.py: find_correlation_tagged_events(con, sources)
-- Finds every distinct correlation_id value and how many events/sources
-- carry it.
--
-- Run once per source in {auth, web, dns, firewall, endpoint}:
SELECT 'auth' AS source, record.correlation_id AS correlation_id
FROM raw_auth
WHERE record.correlation_id IS NOT NULL;
-- (repeat with raw_web, raw_dns, raw_firewall, raw_endpoint; web/dns raise
--  BinderException by design and are caught + skipped, not queried further)

