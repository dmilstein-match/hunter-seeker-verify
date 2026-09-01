#!/usr/bin/env python3
"""Verify a Verdict against the LIVE JWKS and report whether vectors.json was cut with a live key.

    python scripts/check_live.py verdict.json signature.json
    python scripts/check_live.py --vectors
"""
import json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "python"))
from hs_verify import fetch_jwks, verify, JWKS_URL  # noqa: E402

try:
    jwks = fetch_jwks()
except Exception as e:  # noqa: BLE001
    print(f"JWKS not reachable at {JWKS_URL}: {e}\nThe engine has not published its signing keys yet; vectors.json cannot be live.")
    sys.exit(1)
live_kids = {k["kid"] for k in jwks.get("keys", [])}
if "--vectors" in sys.argv:
    vec = json.loads((pathlib.Path(__file__).parents[1] / "vectors.json").read_text())
    kid = vec["signature"]["kid"]
    print(f"live kids: {sorted(live_kids)}")
    print(f"vectors kid: {kid} — {'LIVE' if kid in live_kids else 'pre-release / test key (re-cut before publishing)'}")
    sys.exit(0 if kid in live_kids else 1)
v, s = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
print(verify(v, s, jwks=jwks))
