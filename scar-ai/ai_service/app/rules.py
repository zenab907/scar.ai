"""Deterministic, explainable PASSIVE rules. No active probing, ever (Zero-Exploit policy)."""
from dataclasses import dataclass, field

from .baseline import Baseline
from .features import is_wifi
from .schemas import Event


@dataclass
class RuleOutcome:
    score: int = 5
    category: str = "benign"
    findings: list[str] = field(default_factory=list)
    hits: dict[str, int] = field(default_factory=dict)  # category -> score


def _hit(out: RuleOutcome, category: str, score: int, text: str) -> None:
    out.findings.append(text)
    out.hits[category] = max(out.hits.get(category, 0), score)


def evaluate(event: Event, baseline: Baseline) -> RuleOutcome:
    out = RuleOutcome()

    if is_wifi(event):
        enc = (event.encryption or "").upper()
        if enc == "OPEN":
            _hit(out, "weak_encryption", 70, "Network is open (no encryption).")
        elif enc == "WEP":
            _hit(out, "weak_encryption", 75, "WEP is broken and should be retired.")
        elif enc == "WPA":
            _hit(out, "weak_encryption", 50, "Legacy WPA (TKIP) in use; migrate to WPA2/WPA3.")

        if not baseline.empty:
            known = baseline.knows_bssid(event.bssid)
            if baseline.knows_ssid(event.ssid) and not known:
                _hit(out, "rogue_ap", 90,
                     f"SSID '{event.ssid}' belongs to the organization but BSSID {event.bssid} "
                     "is not an authorized access point (possible evil twin).")
            elif not known:
                _hit(out, "unknown_device", 55,
                     f"BSSID {event.bssid} is not in the authorized asset list (possible shadow IT).")

        if not event.ssid:
            _hit(out, "hidden_ssid", 25, "Hidden SSID broadcast.")

    level = (event.raw_payload.get("rule") or {}).get("level")
    if event.source == "wazuh" and isinstance(level, (int, float)):
        desc = (event.raw_payload.get("rule") or {}).get("description", "Wazuh alert")
        _hit(out, "host_alert", min(100, int(level * 7)), f"Wazuh level {level}: {desc}")
    if event.source == "zeek" and event.event_type.startswith("notice"):
        _hit(out, "network_alert", 60, f"Zeek notice: {event.raw_payload.get('msg', event.event_type)}")

    if out.hits:
        out.category = max(out.hits, key=out.hits.get)
        out.score = out.hits[out.category]
    else:
        out.findings.append("No rule matched.")
    return out
