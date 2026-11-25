from .baseline import Baseline
from .schemas import Event

ENC_SCORE = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
FEATURE_NAMES = ["rssi", "band_5ghz", "enc_score", "bssid_known", "ssid_collision"]


def is_wifi(event: Event) -> bool:
    return bool(event.bssid) or event.event_type.startswith("wifi")


def enc_score(enc: str | None) -> int:
    if not enc:
        return 2
    return ENC_SCORE.get(enc.strip().upper(), 2)


def event_features(event: Event, baseline: Baseline) -> list[float]:
    if baseline.empty:
        known, collision = 0.5, 0.0   # cannot judge without a baseline
    else:
        known = 1.0 if baseline.knows_bssid(event.bssid) else 0.0
        collision = 1.0 if (baseline.knows_ssid(event.ssid) and not known) else 0.0
    return [
        float(event.rssi if event.rssi is not None else -90),
        1.0 if (event.channel or 0) > 14 else 0.0,
        float(enc_score(event.encryption)),
        known,
        collision,
    ]
