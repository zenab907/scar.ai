"""Digital Twin (MVP): estimated AP positions + signal heatmap in local metres (x,y) for the dashboard."""
import math
from collections import defaultdict
from typing import Optional

from .baseline import Baseline, norm_mac


def to_xy(lat: float, lon: float, lat0: float, lon0: float) -> tuple[float, float]:
    return (lon - lon0) * 111320.0 * math.cos(math.radians(lat0)), (lat - lat0) * 110540.0


def build_twin(zone: dict, events: list[dict], baseline: Baseline, risk_by_bssid: Optional[dict] = None,
               cell_m: float = 10.0) -> dict:
    risk_by_bssid = {norm_mac(k): v for k, v in (risk_by_bssid or {}).items()}
    lat0, lon0 = zone["origin_lat"], zone["origin_lon"]
    w, h = zone.get("width_m", 300), zone.get("height_m", 200)

    readings, by_ap = [], defaultdict(list)
    for e in events:
        if e.get("bssid") and e.get("rssi") is not None and e.get("lat") is not None:
            x, y = to_xy(e["lat"], e["lon"], lat0, lon0)
            readings.append({"bssid": norm_mac(e["bssid"]), "mission_id": e.get("mission_id"),
                             "rssi": e["rssi"], "lat": e["lat"], "lon": e["lon"], "x": round(x, 1), "y": round(y, 1),
                             "timestamp": e.get("timestamp")})
            by_ap[norm_mac(e["bssid"])].append((x, y, e))

    assets = []
    for bssid, obs in by_ap.items():
        wts = [10 ** (o[2]["rssi"] / 10.0) for o in obs]          # linear power weights
        sw = sum(wts)
        ax = sum(o[0] * wt for o, wt in zip(obs, wts)) / sw
        ay = sum(o[1] * wt for o, wt in zip(obs, wts)) / sw
        ts = sorted(o[2].get("timestamp") or "" for o in obs)
        ssid = next((o[2].get("ssid") for o in obs if o[2].get("ssid")), None)
        enc = obs[0][2].get("encryption")
        assets.append({
            "asset_type": "access_point", "bssid": bssid, "ssid": ssid, "encryption": enc,
            "zone_id": zone.get("zone_id"), "x": round(ax, 1), "y": round(ay, 1),
            "lat": lat0 + ay / 110540.0, "lon": lon0 + ax / (111320.0 * math.cos(math.radians(lat0))),
            "authorized": (None if baseline.empty else baseline.knows_bssid(bssid)),
            "first_seen": ts[0], "last_seen": ts[-1], "observations": len(obs),
            "max_rssi": max(o[2]["rssi"] for o in obs), "current_risk_score": risk_by_bssid.get(bssid, 0),
        })

    nx, ny = max(1, int(math.ceil(w / cell_m))), max(1, int(math.ceil(h / cell_m)))
    sums, cnts = [[0.0] * nx for _ in range(ny)], [[0] * nx for _ in range(ny)]
    for r in readings:
        i, j = int(r["x"] // cell_m), int(r["y"] // cell_m)
        if 0 <= i < nx and 0 <= j < ny:
            sums[j][i] += r["rssi"]; cnts[j][i] += 1
    z = [[(round(sums[j][i] / cnts[j][i], 1) if cnts[j][i] else None) for i in range(nx)] for j in range(ny)]
    return {"zone": zone, "assets": assets, "readings": readings,
            "heatmap": {"cell_m": cell_m, "x_edges": [i * cell_m for i in range(nx + 1)],
                        "y_edges": [j * cell_m for j in range(ny + 1)], "mean_rssi": z}}
