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


# ── the shared cross-language tables (vectors.json) ───────────────────────────────────────────
#
# Both of these caught a real divergence between this library and the TypeScript twin, and neither
# was reachable from the signed `payload`: its largest number is 1, and expiry is checked AFTER the
# signature, so varying expires_at there returns invalid_signature and never reaches the comparison.

def test_canonical_number_rules_match_the_shared_table():
    # Python special-cased `int` and emitted exact digits; TypeScript ran every number through ES6
    # on an IEEE-754 double. Above 2^53 the two produced different canonical bytes for the same
    # document, so one library would call a Verdict valid and the other invalid_signature.
    for c in VEC["canonical_only"]["cases"]:
        assert canonicalize(c["value"]) == c["canonical"], c["name"]


def test_expiry_rules_match_the_shared_table():
    # Both libraries compared ISO strings lexicographically. "+00:00" sorts before "Z", so an
    # offset-form expiry read as unexpired for the rest of the century.
    from datetime import datetime
    from hs_verify import expired_at
    for c in VEC["expiry"]["cases"]:
        now = datetime.fromisoformat(c["now"].replace("Z", "+00:00"))
        assert expired_at(c["expires_at"], now) is c["expired"], c["name"]
