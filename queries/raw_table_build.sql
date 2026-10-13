-- src/cli.py: builds one raw_<source> table per source (auth, web, dns,
-- firewall, endpoint) with a source_line column so every row keeps an
-- exact file:line locator downstream, in review.py and hunt.py.
--
-- Parameterized in code as {input_dir}/{source}.jsonl and clean.main.raw_{source};
-- shown here fully substituted for source=auth against the real archive.
-- Run against clean.db.

CREATE OR REPLACE TABLE raw_auth AS
SELECT *, row_number() OVER () AS source_line
FROM read_json_auto('source/auth.jsonl', format='newline_delimited', ignore_errors=true);

-- Repeated identically for web, dns, firewall, endpoint (see src/cli.py SOURCES loop).
