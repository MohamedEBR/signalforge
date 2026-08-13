import json
from pathlib import Path

import pytest

from signalforge.normalize import NormalizationError, detect_source, normalize

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("scenario", "expected_sources"),
    [
        ("aws_role_chain", {"aws.cloudtrail"}),
        ("entra_privilege", {"microsoft.entra"}),
        ("network_api", {"sentinelflow", "application.auth"}),
        ("aegis_revoked", {"aegis.audit"}),
    ],
)
def test_normalizes_supported_sources(
    scenario: str, expected_sources: set[str]
) -> None:
    lines = (ROOT / "scenarios" / scenario / "events.jsonl").read_text().splitlines()
    events = [normalize(json.loads(line)) for line in lines if line]

    assert {event.source for event in events} == expected_sources
    assert all(event.time.tzinfo is not None for event in events)
    assert all(event.id for event in events)


def test_cloudtrail_preserves_detection_observables() -> None:
    raw = json.loads(
        (ROOT / "scenarios/aws_role_chain/events.jsonl").read_text().splitlines()[0]
    )
    event = normalize(raw)

    assert event.actor and event.actor.id.endswith("user/alice")
    assert event.source_endpoint and event.source_endpoint.ip == "198.51.100.24"
    assert event.observables["access_key_id"] == "AKIASYNTHETIC0001"


def test_invalid_ip_is_not_promoted_to_an_entity() -> None:
    event = normalize(
        {
            "schema_version": "application.auth.v1",
            "id": "bad-ip",
            "time": "2026-08-13T00:00:00Z",
            "principal": "demo",
            "source_ip": "not-an-ip",
            "outcome": "failure",
        }
    )

    assert event.source_endpoint
    assert event.source_endpoint.ip is None
    assert not any(entity.type == "ip" for entity in event.entities())


def test_aegis_unknown_outcome_remains_unknown() -> None:
    event = normalize(
        {
            "sequence": 1,
            "timestamp": "2026-08-13T00:00:00Z",
            "type": "token_exchange",
            "hash": "synthetic",
            "outcome": "pending",
        }
    )

    assert event.outcome == "unknown"


def test_unknown_and_invalid_sources_are_rejected() -> None:
    with pytest.raises(NormalizationError, match="could not be detected"):
        detect_source({"message": "no discriminator"})
    with pytest.raises(NormalizationError, match="unsupported source"):
        normalize({}, "unknown.adapter")
    with pytest.raises(NormalizationError, match="invalid application.auth"):
        normalize({"schema_version": "application.auth.v1"})
