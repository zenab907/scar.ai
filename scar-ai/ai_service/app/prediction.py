"""Prediction Agent: IsolationForest anomaly detector trained on a *normal* synthetic baseline.

MVP note: swap `_training_matrix()` for real, customer-approved, clean mission data when you have it.
"""
import time

import numpy as np
from sklearn.ensemble import IsolationForest

from .baseline import Baseline
from .features import FEATURE_NAMES, event_features, is_wifi
from .schemas import AgentResult, AuthorizedAsset, Event
from . import synthetic

MODEL_VERSION = "iforest-v0.1"


def _severity(score: int) -> str:
    return "low" if score < 30 else "medium" if score < 60 else "high" if score < 80 else "critical"


class PredictionAgent:
    def __init__(self, seed: int = 42):
        self.model = IsolationForest(n_estimators=200, contamination=0.05, random_state=seed)
        self.model.fit(self._training_matrix())

    @staticmethod
    def _training_matrix() -> np.ndarray:
        """Mostly-clean historical flights + ~4% unlabeled noise.

        IsolationForest never splits on a constant feature, so a perfectly clean set would make it blind to
        `bssid_known` / `ssid_collision`. A few percent of unknown observations (realistic: history is never
        perfectly clean) teaches it that those features can vary - and that "unknown" is rare.
        """
        import random
        rng = random.Random(0)
        base = Baseline([AuthorizedAsset(**a) for a in synthetic.authorized_assets()])
        auth = {a["bssid"] for a in synthetic.authorized_assets()}
        rows = []
        for seed in range(8):
            for e in synthetic.generate_events(seed=seed):
                if e["bssid"] in auth or rng.random() < 0.04:
                    rows.append(event_features(Event(**e), base))
        return np.array(rows)

    def anomaly_score(self, features: list[float]) -> int:
        s = -float(self.model.score_samples(np.array([features]))[0])   # ~0.35 normal .. 0.7 anomalous
        return int(round(min(1.0, max(0.0, (s - 0.40) / 0.22)) * 100))

    def predict(self, event: Event, baseline: Baseline) -> AgentResult:
        t0 = time.perf_counter()
        if not is_wifi(event):
            return AgentResult(
                event_id=event.event_id, agent="prediction", model_version=MODEL_VERSION,
                severity="low", risk_score=0, category="benign", confidence=0.0,
                explanation="Not a Wi-Fi observation; the anomaly model does not apply.",
                recommended_action="None.", features={"applicable": False},
                processing_ms=int((time.perf_counter() - t0) * 1000))
        feats = event_features(event, baseline)
        score = self.anomaly_score(feats)
        return AgentResult(
            event_id=event.event_id, agent="prediction", model_version=MODEL_VERSION,
            severity=_severity(score), risk_score=score, category="benign" if score < 60 else "unknown_device",
            confidence=round(min(0.9, 0.5 + abs(score - 50) / 100), 2),
            explanation=f"Anomaly score {score}/100 versus the clean-flight baseline.",
            recommended_action="Review together with the rule-based findings." if score >= 60 else "None.",
            features={"applicable": True, **dict(zip(FEATURE_NAMES, feats))},
            processing_ms=int((time.perf_counter() - t0) * 1000))
