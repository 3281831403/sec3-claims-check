"""Token claim decoding and validation."""

from __future__ import annotations

import base64
import json
import math
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
    # Aware datetimes keep their own offset; naive ones are interpreted locally.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_LOCAL_TZ)
    return parsed.timestamp()


def _coerce_time(value):
    if isinstance(value, bool):
        # bool must survive as bool so strict type checks can reject it
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
    # bool is a subclass of int but is never a valid numeric claim
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float))


def _is_finite_number(value) -> bool:
    return _is_number(value) and math.isfinite(value)


def _is_audience(value) -> bool:
    if isinstance(value, str):
        return True
    # An empty audience can never identify a recipient, so it is invalid.
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(item, str) for item in value)
    )


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
    """Return True when the token is valid at ``now`` (endpoint inclusive).

    A token whose ``exp`` equals ``now`` is still accepted; any later
    timestamp is expired. Missing, non-numeric or non-finite ``exp`` fails
    closed, so a tampered or malformed token can never gain access.
    """
    exp = claims.get("exp")
    if not _is_finite_number(exp):
        return False
    return float(now) <= float(exp)


def check_not_before(claims, now, skew):
    """Return True when ``nbf`` has been reached, allowing ``skew`` leeway.

    The endpoint is inclusive: ``now + skew == nbf`` is accepted.
    """
    nbf = claims.get("nbf")
    if nbf is None:
        return True
    if not _is_finite_number(nbf):
        return False
    return float(now) + float(skew) >= float(nbf)


def check_issued_at(claims, now, skew):
    """Return True when ``iat`` is no more than ``skew`` seconds in the future.

    The endpoint is inclusive: ``iat == now + skew`` is accepted. A claim
    issued too far in the future (a tampered token) is rejected.
    """
    iat = claims.get("iat")
    if iat is None:
        return True
    if not _is_finite_number(iat):
        return False
    return float(iat) <= float(now) + float(skew)


def check_audience(claims, client):
    """Audience must match exactly.

    Prefix matching (``startswith``) would let ``reports-admin`` impersonate
    ``reports``. A list audience requires an exact member match. Missing,
    empty or wrongly typed audiences fail closed.
    """
    audience = claims.get("aud")
    if isinstance(audience, str):
        return audience == client
    if isinstance(audience, list):
        return all(isinstance(entry, str) for entry in audience) and client in audience
    return False


def check_types(claims, schema):
    """Validate claim types strictly.

    Numeric strings are not numbers, and ``bool`` is not an ``int`` even
    though it subclasses it. A float is not accepted where an int is required.
    """
    for name, expected in schema.items():
        if name not in claims:
            continue
        value = claims[name]
        if expected is int:
            if isinstance(value, bool) or not isinstance(value, int):
                return False
        elif expected is float:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False
        elif not isinstance(value, expected):
            return False
    return True


def validate_claims(claims):
    """Return problem labels; an empty list means the claims are sound.

    Time and numeric claims must have the correct type and be non-negative;
    the audience must be a string or a non-empty list of strings.
    """
    problems = []
    for name in _TIME_CLAIMS:
        if name not in claims:
            continue
        value = claims[name]
        if not _is_number(value):
            problems.append(f"invalid_type:{name}")
        elif not math.isfinite(value) or value < 0:
            problems.append(f"negative:{name}")
    if "aud" in claims and not _is_audience(claims["aud"]):
        problems.append("invalid_type:aud")
    for name, value in claims.items():
        if name in _TIME_CLAIMS or name == "aud":
            continue
        if _is_number(value) and (not math.isfinite(value) or value < 0):
            problems.append(f"negative:{name}")
    return problems


def claims_batch(tokens, now, schema):
    """Validate every token independently.

    Each token is parsed and judged on its own: an expired, malformed,
    wrongly typed or future-dated token is rejected without affecting any
    other token in the batch.
    """
    results = {}
    for token in tokens:
        try:
            claims = parse_claims(token)
        except (TypeError, ValueError):
            results[token] = False
            continue
        problems = validate_claims(claims)
        if not check_types(claims, schema):
            problems.append("invalid_type:schema")
        if not check_expiry(claims, now):
            problems.append("expired")
        if not check_not_before(claims, now, 0):
            problems.append("not_yet_valid")
        if not check_issued_at(claims, now, 0):
            problems.append("issued_in_future")
        results[token] = not problems
    return results
