import json, pathlib
from datetime import datetime, timezone
from hs_verify import verify, canonicalize

VEC = json.loads((pathlib.Path(__file__).parents[2] / "vectors.json").read_text())

def test_canonical_matches_engine():
    assert canonicalize(VEC["payload"]) == VEC["canonical"]

def test_valid_tampered_expired_unknown():
    assert verify(VEC["payload"], VEC["signature"], jwks=VEC["jwks"]) == "valid"
    assert verify(VEC["tampered"], VEC["signature"], jwks=VEC["jwks"]) == "invalid_signature"
    assert verify(VEC["payload"], VEC["signature"], jwks={"keys": []}) == "unknown_key"
    assert verify(VEC["payload"], VEC["signature"], jwks=VEC["jwks"], now=datetime(2100, 1, 1, tzinfo=timezone.utc)) == "expired"


def test_a_real_production_verdict_verifies_offline():
    """The vectors above are synthetic on purpose — they carry the canonicalisation edge cases.
    This one is a REAL Verdict emitted by production and signed by the production key, which is
    the claim the whole library exists to support: anyone can check a decision, with no account
    and no server.

    Its `valid` check is pinned to verify_at because a real Verdict has a real expires_at. An
    unpinned assertion would turn this suite red on that date for no reason but the calendar.
    """
    live = VEC["live"]
    at = datetime.fromisoformat(live["verify_at"].replace("Z", "+00:00"))
    assert verify(live["verdict"], live["signature"], jwks=VEC["jwks"], now=at) == live["expected"]["valid"]
    after = datetime.fromisoformat(live["verdict"]["expires_at"].replace("Z", "+00:00"))
    assert verify(live["verdict"], live["signature"], jwks=VEC["jwks"],
                  now=after.replace(year=after.year + 1)) == live["expected"]["expired_after_window"]
    assert verify(live["verdict"], live["signature"], jwks={"keys": []}, now=at) == "unknown_key"


def test_the_real_verdict_is_signed_by_the_key_we_publish():
    """vectors.json ships its own copy of the JWKS. If that copy ever drifts from the kid the
    signature names, the tests above would still pass against the stale copy while every real
    reviewer failed. scripts/check_live.py --vectors is the online half of this check."""
    assert VEC["live"]["signature"]["kid"] in {k["kid"] for k in VEC["jwks"]["keys"]}
