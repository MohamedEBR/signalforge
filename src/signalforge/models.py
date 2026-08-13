from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["informational", "low", "medium", "high", "critical"]
Outcome = Literal["success", "failure", "unknown"]


class Entity(BaseModel):
    type: str
    id: str
    name: str | None = None


class Endpoint(BaseModel):
    ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    hostname: str | None = None
    country: str | None = None


class SecurityEvent(BaseModel):
    """A deliberately small OCSF-inspired event envelope."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "signalforge.event.v1"
    id: str = Field(min_length=1, max_length=256)
    time: datetime
    source: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")
    category: str
    activity: str
    outcome: Outcome = "unknown"
    severity: Severity = "informational"
    actor: Entity | None = None
    source_endpoint: Endpoint | None = None
    target: Entity | None = None
    observables: dict[str, str | int | float | bool] = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list)
    raw_ref: str | None = None

    @field_validator("time")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("event time must include a timezone")
        return value.astimezone(UTC)

    def field_value(self, path: str) -> Any:
        value: Any = self
        for part in path.split("."):
            if isinstance(value, BaseModel):
                value = getattr(value, part, None)
            elif isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    def entities(self) -> list[Entity]:
        result: list[Entity] = []
        if self.actor:
            result.append(self.actor)
        if self.target:
            result.append(self.target)
        if self.source_endpoint and self.source_endpoint.ip:
            result.append(Entity(type="ip", id=self.source_endpoint.ip))
        return result


class Predicate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    op: Literal[
        "eq", "ne", "in", "not_in", "exists", "contains", "regex", "cidr", "gte", "lte"
    ] = "eq"
    value: Any = None


class EventMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[str] = Field(default_factory=list)
    activities: list[str] = Field(default_factory=list)
    outcomes: list[Outcome] = Field(default_factory=list)
    all: list[Predicate] = Field(default_factory=list)
    none: list[Predicate] = Field(default_factory=list)


class RuleStage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    match: EventMatch


class ResponseAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    target_field: str
    description: str
    approval_required: Literal[True] = True


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^SF-[A-Z0-9-]+$")
    version: int = Field(default=1, ge=1)
    name: str
    author: str = "Mohamed Ebraheem"
    description: str
    type: Literal["match", "threshold", "sequence"]
    severity: Severity
    status: Literal["experimental", "test", "stable", "deprecated"] = "experimental"
    required_sources: list[str] = Field(min_length=1)
    tactics: list[str] = Field(min_length=1)
    techniques: list[str] = Field(min_length=1)
    false_positives: list[str] = Field(min_length=1)
    group_by: list[str] = Field(default_factory=list)
    window: str = "5m"
    threshold: int = Field(default=1, ge=1, le=10000)
    match: EventMatch | None = None
    stages: list[RuleStage] = Field(default_factory=list)
    runbook: list[str] = Field(min_length=1)
    responses: list[ResponseAction] = Field(default_factory=list)

    @field_validator("stages")
    @classmethod
    def bound_stages(cls, value: list[RuleStage]) -> list[RuleStage]:
        if len(value) > 12:
            raise ValueError("sequence rules support at most 12 stages")
        return value


class Finding(BaseModel):
    schema_version: str = "signalforge.finding.v1"
    id: str
    rule_id: str
    rule_version: int
    rule_name: str
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    detected_at: datetime
    group: list[str]
    matched_event_ids: list[str]
    evidence: list[str]
    entities: list[Entity]
    tactics: list[str]
    techniques: list[str]
    runbook: list[str]


class ResponsePlan(BaseModel):
    action: str
    target: str | None
    description: str
    status: Literal["pending_approval"] = "pending_approval"
    executable: Literal[False] = False


class Incident(BaseModel):
    schema_version: str = "signalforge.incident.v1"
    id: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    finding_ids: list[str]
    rule_ids: list[str]
    entities: list[Entity]
    evidence: list[str]
    timeline: list[str]
    tactics: list[str]
    techniques: list[str]
    response_plans: list[ResponsePlan]
    explanation: str


class ScenarioExpectation(BaseModel):
    expected_rules: list[str] = Field(default_factory=list)
    forbidden_rules: list[str] = Field(default_factory=list)


class ScenarioResult(BaseModel):
    name: str
    event_count: int
    finding_count: int
    incident_count: int
    fired_rules: list[str]
    expected_rules: list[str]
    forbidden_rules: list[str]
    passed: bool
    missing_rules: list[str]
    unexpected_rules: list[str]
    engine_ms: float
    findings: list[Finding]
    incidents: list[Incident]


class ReplayReport(BaseModel):
    schema_version: str = "signalforge.replay.v1"
    generated_at: datetime
    scenario_count: int
    passed_scenarios: int
    failed_scenarios: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    median_engine_ms: float
    scenarios: list[ScenarioResult]
