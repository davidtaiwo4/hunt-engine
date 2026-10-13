# hunt-engine

A Python and DuckDB pipeline that ingests raw security logs, normalizes mixed schema versions, quarantines bad records with traceable locators, and runs reusable hunt queries across sources to reconstruct attack chains.

Built and tested against roughly 750,000 events across five sources: authentication, web, DNS, firewall, and endpoint.

## The problem

- Each source is a JSONL file that mixes three schema versions in one file.
- The same logical field changes name between versions. A hostname can be `host`, `device`, or nested inside a `record` object.
- Some rows are malformed JSON, have no timestamp, or carry a schema tag with every value null.
- Real attack activity is only visible when events from several sources are joined on identity, host, and time.
- 96 flagged activities had to be classified as legitimate or a real violation, using raw log evidence and the controlling change record.

## Results

### Three attack chains reconstructed

Each chain is supported by exact `file:line` locators in at least two sources, a rejected alternative hypothesis, and a next collection action.

**1. Password spray to encoded PowerShell (auth, firewall, endpoint)**
One external IP made one failed login per day against a VPN gateway for 12 consecutive days, always at the same time of day, using a different sequential username each day. On day 13 a login succeeded with MFA recorded as push-approved. The firewall logged an allowed connection from the same IP 8 seconds later. About 66 minutes after the login, the endpoint source recorded an encoded PowerShell command under the same identity, written in a different alias format (`user@domain` in auth, `DOMAIN\user` on the endpoint). `identity.py` resolves the two aliases to one person, which is what lets the chain join across sources.
Rejected: one user mistyping a password repeatedly. The fixed daily cadence, single source IP, and different account each day do not fit.

**2. Large unattributed outbound transfer (firewall, auth, endpoint)**
A shared gateway sent about 885 KB to an external IP and the firewall allowed it. Among roughly 100 external destinations in the data, this was the only one with no recurring pattern, and by far the largest single transfer. The only login on that gateway that day was 8 hours earlier, and the nearest endpoint activity belonged to a different user.
Rejected: the transfer belonging to the earlier login. The gap is too large and no session spans it.

**3. Removable media copy with no authentication trail (endpoint, auth)**
A sensitive file was copied to a USB device on a host that appears nowhere in the auth source, in any schema version. The identity on the copy had logged in once that day, on a different host, 66 minutes earlier. `file_copy` occurs once in about 150,000 endpoint events.
Rejected: the user logging in remotely and then using their own machine. No login of any kind exists for the host where the copy happened.

How they were found: first by manual exploration (rarity scans, joins across sources, timeline pulls), then re-expressed as the parameterized functions in `hunt.py`. Running those functions with generic thresholds independently surfaces the same rare event, the same external outlier, and the same spray pattern.

### 96 flagged activities classified: 80 benign, 16 escalated

Every activity was resolved from raw log rows tagged with its `activity_id` and the controlling change record. A benign verdict required asset, actor, approval status and time window to all match.

Escalated activities are the true positives and benign ones are the false positives.

## How it works

```
source/*.jsonl
    -> ingest.py     line-by-line JSON parse, every line accounted for
    -> normalize.py  schema_version dispatch, one output shape
    -> cli.py        quarantine.csv, reconciliation.json, results.json, clean.db
    -> hunt.py       parameterized DuckDB hunt queries
    -> review.py     reconcile flagged activities against change records
```

Nothing is silently dropped. A row that fails parsing or normalization goes to `quarantine.csv` with a stable reason code (`invalid_json`, `empty_line`, `missing_time`, `unknown_schema_version`, `incomplete_fields`) and an exact `file:line` locator. `reconciliation.json` reports raw, normalized, and quarantined counts per source so totals can be checked against a manifest.

## Repository layout

```
hunt-engine/
├── Makefile
├── README.md
├── requirements.txt
├── src/
│   ├── cli.py         pipeline entry point
│   ├── ingest.py      parse_json_line, read_source_file (line-tracking reader)
│   ├── normalize.py   config-driven normalize_row(source, row)
│   ├── clock.py       apply_offset, infer_offset_seconds
│   ├── identity.py    canonicalize_identity (email and DOMAIN\user aliases)
│   ├── hunt.py        reusable hunt primitives
│   ├── run_hunt.py    runs the hunt functions with chosen parameters
│   ├── review.py      activity reconciliation against change records
│   └── build_tp_fp_table.py
├── tests/
└── queries/           saved SQL used during investigation
```

## Setup

Requires Python 3.11 or newer.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Place the five source files in `source/` named `auth.jsonl`, `web.jsonl`, `dns.jsonl`, `firewall.jsonl`, `endpoint.jsonl`.

```bash
make test                    # run the pytest suite
make build INPUT=source      # ingest, normalize, quarantine, build clean.db
python3 -m src.run_hunt      # run the hunt functions against clean.db
```

`make build` writes `clean.db`, `quarantine.csv`, `reconciliation.json`, and `results.json`.

## Schema handling

| Concept | v1 | v2 | v3 |
|---|---|---|---|
| time | `timestamp` | `event_time` | `time` |
| host | `host` | `device` | `record.host` |
| identity | `username` or `user` | `identity` | `record.username` |
| outcome | `action` | `result` | `record.action` |

`normalize.py` holds this mapping as configuration (`SOURCE_FIELD_MAP`, `SOURCE_CONSTANTS`), so adding a source means adding config entries, not another function.

## Hunt functions

`hunt.py` takes thresholds as arguments. No IPs, users, hosts, or timestamps are hardcoded.

- `find_rare_field_values`: values occurring at or below a given count
- `find_external_destinations`: firewall destinations outside given internal prefixes, ranked by bytes
- `find_login_spray_pattern`: failed logins from one source to one target across a minimum number of distinct days
- `find_correlation_tagged_events` and `get_events_for_tag`: events sharing a tag across sources
- `find_unattributed_activity`: activity with no covering auth session in a time window

Helpers `resolve_host`, `resolve_identity`, and `resolve_ip` return SQL `COALESCE` fragments that cover all three schema versions.

## Review reconciliation

`review.py` takes each flagged activity, finds every raw row tagged with its `activity_id` (top-level or nested in `record`), and compares asset, actor, approval status, and time window against the controlling change record. The time window is checked against the earliest tagged event, since an approval window authorizes when an activity starts. Any mismatch is escalated with a reason code; full matches are benign.

## Testing

The suite was written test-first with pytest. It covers every schema version for each source, malformed JSON, empty lines, missing and null timestamps, unknown schema versions, identity aliases, clock offsets, and line-number tracking.

One test caught a real defect: rows with a schema tag but all-null values were passing as normalized with empty fields. The fix checks actual values, not key presence.

## Data note

Source logs and investigation outputs are not included in this repository.
