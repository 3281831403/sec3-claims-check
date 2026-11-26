import base64
import json
from datetime import datetime

from claims import (
    check_audience,
    check_expiry,
    check_types,
    claims_batch,
    parse_claims,
)

NOW = 1_800_000_000


def _encode(payload):
    def segment(value):
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{segment({'alg': 'HS256', 'typ': 'JWT'})}.{segment(payload)}.c2ln"


def test_public_parse_claims():
    token = _encode(
        {
            "sub": "alice",
            "aud": "reports",
            "exp": "2026-12-01T08:00:00+09:45",
        }
    )

    claims = parse_claims(token)
    expected = datetime.fromisoformat("2026-12-01T08:00:00+09:45").timestamp()

    assert claims["sub"] == "alice"
    assert claims["aud"] == "reports"
    assert abs(claims["exp"] - expected) < 0.001


def test_public_expiry_rejects_expired():
    assert check_expiry({"exp": NOW}, NOW) is True
    assert check_expiry({"exp": NOW - 1}, NOW) is False


def test_public_audience_exact_match():
    assert check_audience({"aud": "reports"}, "reports") is True
    assert check_audience({"aud": "reports"}, "reports-admin") is False


def test_public_types_reject_string_number():
    schema = {"count": int, "ratio": float}

    assert check_types({"count": 3, "ratio": 0.5}, schema) is True
    assert check_types({"count": "3", "ratio": 0.5}, schema) is False


def test_public_batch_tokens_independent():
    valid = _encode({"exp": NOW + 600})
    expired = _encode({"exp": NOW - 600})

    result = claims_batch([valid, expired], NOW, {})

    assert result[valid] is True
    assert result[expired] is False