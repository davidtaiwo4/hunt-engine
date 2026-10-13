import json
import csv

with open("review_results_raw.json") as f:
    results = json.load(f)

with open("tp-fp-table.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "activityId", "verdict", "reasons",
        "change_record_locator", "evidence_locator",
        "change_asset", "change_actor", "change_status",
        "change_startsAt", "change_endsAt", "raw_event_count"
    ])
    writer.writeheader()
    for r in results:
        writer.writerow({
            "activityId": r["activityId"],
            "verdict": "true_positive" if r["verdict"] == "escalate" else "false_positive",
            "reasons": "; ".join(r["mismatches"]) if r["mismatches"] else "reconciled: activity, asset, actor, approval, and time window all match",
            "change_record_locator": r.get("change_record_locator"),
            "evidence_locator": r.get("controlling_locator"),
            "change_asset": r["change_asset"],
            "change_actor": r["change_actor"],
            "change_status": r["change_status"],
            "change_startsAt": r["change_startsAt"],
            "change_endsAt": r["change_endsAt"],
            "raw_event_count": r["raw_event_count"],
        })

print("Wrote tp-fp-table.csv")
