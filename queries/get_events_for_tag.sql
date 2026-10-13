-- src/hunt.py: get_events_for_tag(con, tag_field, tag_value, sources)
-- Pulls every raw row where tag_field = tag_value, across all given
-- sources, in time order. tag_value is supplied by the caller 
--
-- Shown here with the actual parameters run_hunt.py passes after
-- discovering spray-v1: tag_field='correlation_id', tag_value='spray-v1'.

-- Run once per source in {auth, web, dns, firewall, endpoint}, parameterized:
SELECT 'auth' AS source, *
FROM raw_auth
WHERE record.correlation_id = 'spray-v1';
-- (repeat with raw_firewall, raw_endpoint; raw_web/raw_dns raise
--  BinderException and are caught + skipped)
