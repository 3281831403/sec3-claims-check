"""Token claim decoding and validation."""

from __future__ import annotations

import base64
import json
from datetime import datetime

_TIME_CLAIMS = ("exp", "nbf", "iat")
_LOCAL_TZ = datetime.now().astimezone().tzinfo


def _decode_segment(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError("token contains an undecodable segment") from exc


def _parse_iso_time(value: str) -> float:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid time declaration: {value!r}") from exc
    parsed = parsed.replace(tzinfo=None)
    parsed = parsed.replace(tzinfo=_LOCAL_TZ)
    return parsed.timestamp()


def _coerce_time(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return _parse_iso_time(value)
    return value


def _is_number(value) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        try:
            float(value)
        except ValueError:
            return False
        return True
    return False


def _is_audience(value) -> bool:
    if isinstance(value, str):
        return True
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def parse_claims(token):
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token must contain exactly three segments")
    try:
        payload = json.loads(_decode_segment(parts[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("token payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("token payload must be an object")
    claims = dict(payload)
    for name in _TIME_CLAIMS:
        if name in claims:
            claims[name] = _coerce_time(claims[name])
    return claims


def check_expiry(claims, now):
    exp = claims.get("exp")
    if exp is None:
        return False
    return _is_number(exp)


def check_not_before(claims, now, skew):
    nbf = claims.get("nbf")
    if nbf is None:
        return True
    return _is_number(nbf)


def check_issued_at(claims, now, skew):
    iat = claims.get("iat")
    if iat is None:
        return True
    return _is_number(iat)


def check_audience(claims, client):
    audience = claims.get("aud", "")
    if isinstance(audience, list):
        return any(client.startswith(entry) for entry in audience)
    return client.startswith(audience)


def check_types(claims, schema):
    for name, expected in schema.items():
        if name not in claims:
            continue
        value = claims[name]
        if expected in (int, float):
            if not _is_number(value):
                return False
        elif not isinstance(value, expected):
            return False
    return True


def validate_claims(claims):
    problems = []
    for name in _TIME_CLAIMS:
        if name not in claims:
            continue
        if not _is_number(claims[name]):
            problems.append(f"invalid_type:{name}")
    if "aud" in claims and not _is_audience(claims["aud"]):
        problems.append("invalid_type:aud")
    return problems


def _expired(claims, now):
    exp = claims.get("exp")
    if exp is None:
        return True
    try:
        exp_value = _coerce_time(exp)
    except (TypeError, ValueError):
        return True
    return float(now) > exp_value


def claims_batch(tokens, now, schema):
    results = {}
    cached = None
    for token in tokens:
        if cached is None:
            cached = parse_claims(token)
        claims = cached
        problems = validate_claims(claims)
        if not check_types(claims, schema):
            problems.append("invalid_type:schema")
        if _expired(claims, now):
            problems.append("expired")
        results[token] = not problems
    return results