"""Risk fusion: explainable combination of Sentinel + Prediction (+ rule floor)."""
from .schemas import AgentResult, FinalRisk
from .sentinel import severity_for

W_SENTINEL, W_PREDICTION = 0.6, 0.4
FUSION_VERSION = "risk-fusion-v0.1"


def fuse(sentinel: AgentResult, prediction: AgentResult) -> AgentResult:
    applicable = prediction.features.get("applicable", False)
    if applicable:
        base = W_SENTINEL * sentinel.risk_score + W_PREDICTION * prediction.risk_score
    else:
        base = float(sentinel.risk_score)
    floor_reason = None
    if sentinel.category == "rogue_ap" and base < 85:
        base, floor_reason = 85.0, "rogue_ap floor (min 85)"
    score = int(round(min(100, base)))
    expl = sentinel.explanation
    if applicable:
        expl += f" ML anomaly score: {prediction.risk_score}/100."
    return AgentResult(
        event_id=sentinel.event_id, agent="risk", model_version=FUSION_VERSION,
        severity=severity_for(score), risk_score=score, category=sentinel.category,
        confidence=round((sentinel.confidence + (prediction.confidence if applicable else sentinel.confidence)) / 2, 2),
        explanation=expl.strip(), recommended_action=sentinel.recommended_action,
        features={"sentinel_score": sentinel.risk_score, "prediction_score": prediction.risk_score if applicable else None,
                  "weights": {"sentinel": W_SENTINEL, "prediction": W_PREDICTION if applicable else 0},
                  "floor": floor_reason})


def to_final(r: AgentResult) -> FinalRisk:
    return FinalRisk(risk_score=r.risk_score, severity=r.severity, category=r.category, confidence=r.confidence,
                     explanation=r.explanation, recommended_action=r.recommended_action)
