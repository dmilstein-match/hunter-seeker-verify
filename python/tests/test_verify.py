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
