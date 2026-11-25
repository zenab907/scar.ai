"""Reporting Agent (MVP): turns mission data into a Markdown report. The dashboard / n8n can render or convert it."""
from collections import Counter, defaultdict

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_report(mission: dict, events: list[dict], results: list[dict]) -> str:
    risk_rows = [r for r in results if r.get("agent") == "risk"]
    ev_by_id = {e["event_id"]: e for e in events}
    sev = Counter(r["severity"] for r in risk_rows)

    # group per access point (bssid) so the report is readable, not 1 line per beacon
    per_ap: dict[str, list[dict]] = defaultdict(list)
    for r in risk_rows:
        e = ev_by_id.get(r["event_id"], {})
        per_ap[e.get("bssid") or f"({e.get('source', 'n/a')}) {e.get('event_type', 'event')}"].append(r)

    findings = []
    for key, rows in per_ap.items():
        worst = max(rows, key=lambda x: x["risk_score"])
        e = ev_by_id.get(worst["event_id"], {})
        findings.append((worst, key, e, len(rows)))
    findings.sort(key=lambda f: (ORDER.get(f[0]["severity"], 9), -f[0]["risk_score"]))

    L = [f"# SCAR Mission Report - {mission.get('mission_id', 'n/a')}", "",
         f"- Zone: {mission.get('zone_id', 'n/a')}", f"- Drone: {mission.get('drone_id', 'n/a')}",
         f"- Started: {mission.get('started_at', 'n/a')}   Ended: {mission.get('ended_at', 'n/a')}",
         f"- Observations analyzed: {len(risk_rows)} across {len(per_ap)} distinct sources", "",
         "## Summary", "",
         "| Critical | High | Medium | Low |", "|---|---|---|---|",
         f"| {sev['critical']} | {sev['high']} | {sev['medium']} | {sev['low']} |", "",
         "## Findings (worst observation per source)", ""]
    if not findings:
        L.append("_No analyzed observations._")
    else:
        L += ["| Severity | Score | Source | SSID | Category | Location | Obs. |", "|---|---|---|---|---|---|---|"]
        for w, key, e, n in findings:
            loc = f"{e['lat']:.5f}, {e['lon']:.5f}" if e.get("lat") is not None else "n/a"
            L.append(f"| {w['severity']} | {w['risk_score']} | {key} | {e.get('ssid') or '(hidden)'} | {w['category']} | {loc} | {n} |")
        L += ["", "## Recommended actions", ""]
        seen = set()
        for w, key, e, n in findings:
            if w["severity"] in ("critical", "high", "medium") and (w["category"], w["recommended_action"]) not in seen:
                seen.add((w["category"], w["recommended_action"]))
                L.append(f"- **{w['category']}**: {w['recommended_action']}")
    L += ["", "## Scope & compliance", "",
          "This assessment was passive-only (Zero-Exploit policy): observation of 802.11/Bluetooth signals inside the "
          "geo-fenced, customer-authorized zone. No network was probed, connected to, or modified.", ""]
    return "\n".join(L)
