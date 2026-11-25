"""Synthetic site + drone flight simulator (for demos, tests and ML baseline training)."""
import math
import random
import uuid
from datetime import datetime, timedelta, timezone

ORIGIN = (27.1800, 31.1800)  # demo origin (Assiut area). Replace with the real site.
SITE_W, SITE_H = 300.0, 200.0

# name, bssid, ssid, x, y, enc, channel, authorized
APS = [
    ("lib-1",  "AA:BB:CC:00:00:01", "Campus-WiFi", 50, 40,  "WPA2", 1,  True),
    ("lib-2",  "AA:BB:CC:00:00:02", "Campus-WiFi", 150, 40, "WPA2", 6,  True),
    ("eng-1",  "AA:BB:CC:00:00:03", "Campus-WiFi", 250, 40, "WPA3", 11, True),
    ("admin-1","AA:BB:CC:00:00:04", "Admin-Secure", 60, 150, "WPA3", 36, True),
    ("lab-1",  "AA:BB:CC:00:00:05", "Campus-WiFi", 160, 150, "WPA2", 6, True),
    ("lab-2",  "AA:BB:CC:00:00:06", "Campus-WiFi", 250, 150, "WPA2", 11, True),
    # --- problems ---
    ("rogue",  "DE:AD:BE:EF:00:01", "Campus-WiFi", 200, 100, "WPA2", 6, False),   # evil twin
    ("shadow", "DE:AD:BE:EF:00:02", "Cafeteria-Free", 90, 100, "Open", 1, False),  # open shadow AP
    ("legacy", "DE:AD:BE:EF:00:03", "Old-Lab", 270, 170, "WEP", 11, False),        # WEP
    ("hidden", "DE:AD:BE:EF:00:04", "", 30, 180, "WPA2", 3, False),                # hidden SSID
]


def authorized_assets() -> list[dict]:
    return [{"bssid": a[1], "ssid": a[2]} for a in APS if a[7]]


def xy_to_latlon(x: float, y: float, origin=ORIGIN) -> tuple[float, float]:
    lat0, lon0 = origin
    return lat0 + y / 110540.0, lon0 + x / (111320.0 * math.cos(math.radians(lat0)))


def _rssi(d: float, rng: random.Random, n: float = 3.0) -> int:
    return int(round(-30 - 10 * n * math.log10(max(d, 1.0)) + rng.gauss(0, 3)))


def generate_events(seed: int = 7, mission_id: str | None = None, only_authorized: bool = False,
                    step_m: float = 25.0, altitude: float = 30.0, max_range_m: float = 140.0) -> list[dict]:
    rng = random.Random(seed)
    mission_id = mission_id or "mission-demo-001"
    t = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
    events: list[dict] = []
    ys = [step_m / 2 + i * step_m for i in range(int(SITE_H // step_m))]
    for row, y in enumerate(ys):                      # lawn-mower path
        xs = [i * step_m for i in range(int(SITE_W // step_m) + 1)]
        if row % 2:
            xs.reverse()
        for x in xs:
            t += timedelta(seconds=2)
            lat, lon = xy_to_latlon(x, y)
            for name, bssid, ssid, ax, ay, enc, ch, auth in APS:
                if only_authorized and not auth:
                    continue
                d = math.sqrt((x - ax) ** 2 + (y - ay) ** 2 + altitude ** 2)
                rssi = _rssi(d, rng)
                if d > max_range_m or rssi < -92:
                    continue
                events.append({
                    "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
                    "mission_id": mission_id, "source": "drone", "event_type": "wifi_beacon",
                    "timestamp": t.isoformat(), "bssid": bssid, "ssid": ssid or None,
                    "rssi": rssi, "channel": ch, "encryption": enc,
                    "lat": lat, "lon": lon, "altitude": altitude, "raw_payload": {"sim_ap": name},
                })
    return events
