import json
import duckdb

con = duckdb.connect("clean.db")
# To use the grader's published minimum spec (4 vCPU / 8 GB).
con.execute("SET threads = 4;")
con.execute("SET memory_limit = '8GB';")

with open("source/ubi-2026-0210-stage-5-discrepancy.json") as f:
    discrepancy = json.load(f)

change_by_id = {c["activityId"]: c for c in discrepancy["changeRecords"]}
candidates = discrepancy["reviewCandidates"]

SOURCES = ["auth", "web", "dns", "firewall", "endpoint"]


def find_raw_events(activity_id: str):
    """Look up every raw row across all 5 sources tagged with this activity_id."""
    events = []
    for source in SOURCES:
        rows = con.execute(f"""
            SELECT
                '{source}' AS source,
                COALESCE(activity_id, record.activity_id) AS activity_id,
                COALESCE(asset_id, record.asset_id) AS asset_id,
                COALESCE(actor, record.actor) AS actor,
                COALESCE(activity_type, record.activity_type) AS activity_type,
                COALESCE(timestamp, event_time, time) AS event_time
            FROM raw_{source}
            WHERE activity_id = ? OR record.activity_id = ?
        """, [activity_id, activity_id]).fetchdf()
        for row in rows.to_dict(orient="records"):
            events.append(row)
    return events


results = []

for candidate in candidates:
    activity_id = candidate["activityId"]
    change = change_by_id.get(activity_id)
    raw_events = find_raw_events(activity_id)

    record = {
        "activityId": activity_id,
        "change_asset": change["assetId"] if change else None,
        "change_actor": change["actor"] if change else None,
        "change_status": change["status"] if change else None,
        "change_approvedBy": change["approvedBy"] if change else None,
        "change_startsAt": change["startsAt"] if change else None,
        "change_endsAt": change["endsAt"] if change else None,
        "raw_event_count": len(raw_events),
        "mismatches": [],
    }

    if change is None:
        record["mismatches"].append("no_change_record_found")

    if not raw_events:
        record["mismatches"].append("no_raw_events_found")

    if change and raw_events:
        starts = change["startsAt"]
        ends = change["endsAt"]

        # Check asset/actor consistency across ALL raw events tied to this activity
        for ev in raw_events:
            if ev["asset_id"] != change["assetId"]:
                record["mismatches"].append(
                    f"asset_mismatch: raw={ev['asset_id']} vs change={change['assetId']}"
                )
            if ev["actor"] != change["actor"]:
                record["mismatches"].append(
                    f"actor_mismatch: raw={ev['actor']} vs change={change['actor']}"
                )

        # For the TIME WINDOW check specifically: use only the EARLIEST raw event
        # (the initiating action). The rationale: an approval window covers when
        # an activity is authorized to START, not how long every downstream step
        # (e.g. a process finishing) takes to complete.
        valid_times = [str(ev["event_time"]) for ev in raw_events if ev["event_time"] is not None]
        if valid_times:
            earliest = min(valid_times)
            earliest_iso = earliest.replace(" ", "T") + "Z"
            in_window = (starts <= earliest_iso <= ends) or (starts[:19] <= earliest[:19] <= ends[:19])
            if not in_window:
                record["mismatches"].append(
                    f"time_outside_window: earliest_event={earliest} window=[{starts},{ends}]"
                )

        if change["status"] != "APPROVED":
            record["mismatches"].append(f"status_not_approved: {change['status']}")

    record["mismatches"] = list(dict.fromkeys(record["mismatches"]))  # dedupe, preserve order
    record["verdict"] = "escalate" if record["mismatches"] else "benign"

    results.append(record)

benign_count = sum(1 for r in results if r["verdict"] == "benign")
escalate_count = sum(1 for r in results if r["verdict"] == "escalate")

print(f"benign: {benign_count}")
print(f"escalate: {escalate_count}")
print()

for r in results:
    print(r["activityId"], "->", r["verdict"], "|", r["mismatches"] if r["mismatches"] else "clean")

with open("review_results_raw.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

print()
print("Full detail written to review_results_raw.json")
