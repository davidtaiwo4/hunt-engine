-- src/review.py: find_raw_events(activity_id)
-- Looks up every raw row across all the 5 system logs with a given
-- activity_id, run once per source per candidate.
--
-- Shown here fully substituted for source=auth, activity_id='REVIEW-0048'
-- (an arbitrary real candidate) as example.

SELECT
    'auth' AS source,
    source_line,
    COALESCE(activity_id, record.activity_id) AS activity_id,
    COALESCE(asset_id, record.asset_id) AS asset_id,
    COALESCE(actor, record.actor) AS actor,
    COALESCE(activity_type, record.activity_type) AS activity_type,
    COALESCE(timestamp, event_time, time) AS event_time
FROM raw_auth
WHERE activity_id = 'REVIEW-0048' OR record.activity_id = 'REVIEW-0048';

