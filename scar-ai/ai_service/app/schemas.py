"""Pydantic models = the API contract between n8n / backend / AI service."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]
Category = Literal[
    "rogue_ap", "weak_encryption", "unknown_device", "hidden_ssid",
    "host_alert", "network_alert", "benign",
]


class Event(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_id: str
    mission_id: Optional[str] = None
    source: Literal["wazuh", "zeek", "drone"]
    event_type: str
    timestamp: datetime
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    rssi: Optional[int] = None
    channel: Optional[int] = None
    encryption: Optional[str] = None  # Open / WEP / WPA / WPA2 / WPA3 / Unknown
    lat: Optional[float] = None
    lon: Optional[float] = None
    altitude: Optional[float] = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class AuthorizedAsset(BaseModel):
    bssid: str
    ssid: Optional[str] = None


class Context(BaseModel):
    """Customer baseline (authorized APs). Optional: falls back to data/authorized_assets.json"""
    authorized_assets: list[AuthorizedAsset] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    event: Event
    context: Optional[Context] = None


class AgentResult(BaseModel):
    """One row of the `analysis_results` table."""
    event_id: str
    agent: Literal["sentinel", "prediction", "risk"]
    model_version: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    category: Category
    confidence: float = Field(ge=0, le=1)
    explanation: str
    recommended_action: str
    features: dict[str, Any] = Field(default_factory=dict)
    processing_ms: int = 0
    error: Optional[str] = None


class FinalRisk(BaseModel):
    risk_score: int
    severity: Severity
    category: Category
    confidence: float
    explanation: str
    recommended_action: str


class AnalyzeResponse(BaseModel):
    event_id: str
    results: list[AgentResult]   # sentinel + prediction + risk  -> insert all into analysis_results
    final: FinalRisk             # convenience copy of the "risk" row (used for alert decision)


class ReportRequest(BaseModel):
    mission: dict[str, Any]
    events: list[dict[str, Any]]
    results: list[dict[str, Any]]


class TwinRequest(BaseModel):
    zone: dict[str, Any]                       # {zone_id,name,origin_lat,origin_lon,width_m,height_m}
    events: list[dict[str, Any]]
    risk_by_bssid: dict[str, int] = Field(default_factory=dict)
    cell_m: float = 10.0
    context: Optional[Context] = None
