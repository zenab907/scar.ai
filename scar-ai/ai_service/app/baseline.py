"""Authorized-asset baseline (what the customer says is legitimate)."""
import json
import os
from pathlib import Path
from typing import Optional

from .schemas import AuthorizedAsset, Context

BASELINE_PATH = Path(os.getenv("BASELINE_PATH", Path(__file__).resolve().parent.parent / "data" / "authorized_assets.json"))


def norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.strip().upper().replace("-", ":")


class Baseline:
    def __init__(self, assets: list[AuthorizedAsset]):
        self.assets = assets
        self.bssids = {norm_mac(a.bssid) for a in assets}
        self.ssids = {a.ssid for a in assets if a.ssid}

    @property
    def empty(self) -> bool:
        return not self.assets

    def knows_bssid(self, bssid: Optional[str]) -> bool:
        return norm_mac(bssid) in self.bssids

    def knows_ssid(self, ssid: Optional[str]) -> bool:
        return bool(ssid) and ssid in self.ssids


def load_file_baseline() -> list[AuthorizedAsset]:
    if BASELINE_PATH.exists():
        return [AuthorizedAsset(**a) for a in json.loads(BASELINE_PATH.read_text())]
    return []


def save_file_baseline(assets: list[AuthorizedAsset]) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(json.dumps([a.model_dump() for a in assets], indent=2))


def get_baseline(context: Optional[Context]) -> Baseline:
    """Request context wins; otherwise use the file baseline."""
    if context and context.authorized_assets:
        return Baseline(context.authorized_assets)
    return Baseline(load_file_baseline())
