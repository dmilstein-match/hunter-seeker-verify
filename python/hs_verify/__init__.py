"""hs-verify — keyless verification of a Hunter-Seeker Verdict.

    from hs_verify import verify
    status = verify(verdict, signature)            # fetches the published JWKS
    status = verify(verdict, signature, jwks=jwks) # offline

Returns exactly one of: "valid" | "invalid_signature" | "expired" | "unknown_key".
No account, no API key, no call to Hunter-Seeker beyond fetching the public keys.
Dependencies: `cryptography` only.
"""
from __future__ import annotations

import base64
import json
import os
import math
import urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

JWKS_URL = "https://hunter-seeker.io/.well-known/jwks.json"
__all__ = ["verify", "canonicalize", "fetch_jwks", "JWKS_URL"]

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _s(s: str) -> str:
    return '"' + "".join(_ESC.get(c, f"\\u{ord(c):04x}" if ord(c) < 0x20 else c) for c in s) + '"'


def _n(x: float | int) -> str:
    if isinstance(x, int):
        return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN/Infinity")
    if x == 0:
        return "0"
    if x.is_integer() and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    if "e" in r:
        m, e = r.split("e"); ei = int(e)
        r = f"{m}e{'+' if ei >= 0 else '-'}{abs(ei)}"
    return r


def canonicalize(v: Any) -> str:
    """RFC 8785 JCS (the subset a Verdict uses)."""
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, (int, float)): return _n(v)
    if isinstance(v, str): return _s(v)
    if isinstance(v, (list, tuple)): return "[" + ",".join(canonicalize(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: list(str(kv[0]).encode("utf-16-be")))
        return "{" + ",".join(f"{_s(str(k))}:{canonicalize(x)}" for k, x in items) + "}"
    raise TypeError(type(v).__name__)


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fetch_jwks(url: Optional[str] = None, timeout: float = 5.0) -> dict:
    """Fetch the published keys. `url` defaults to HS_JWKS_URL, else JWKS_URL.

    Resolved at CALL time, not bound as a default argument: a default binds the value at import,
    so `hs_verify.JWKS_URL = ...` silently did nothing and the library kept fetching the public
    host. Anyone self-hosting an engine, or testing against a staging one, hits that — and it
    fails as a 404 that looks like the service being down rather than like a setting being
    ignored.
    """
    url = url or os.environ.get("HS_JWKS_URL") or JWKS_URL
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - https, fixed host
        return json.load(r)


def verify(verdict: Mapping[str, Any], signature: Mapping[str, str], *,
           jwks: Optional[Mapping[str, Any]] = None, now: Optional[datetime] = None) -> str:
    # OUTSIDE the try, deliberately. A JWKS that cannot be fetched is a transport failure, not
    # a verification result: swallowing it into the uniform "invalid_signature" below told the
    # caller a genuine Verdict was FORGED because their DNS was down — the one error that
    # makes an auditor reject a real decision. The four-word contract describes what the
    # verifier concluded about the Verdict; it has no word for "I could not reach the keys",
    # so that stays an exception the caller can see.
    if jwks is None:
        jwks = fetch_jwks()
    try:
        header = json.loads(_b64u(signature["protected"]))
        if header.get("alg") != "EdDSA" or header.get("b64") is not False:
            return "invalid_signature"
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if key is None:
            return "unknown_key"
        pub = Ed25519PublicKey.from_public_bytes(_b64u(key["x"]))
        pub.verify(_b64u(signature["signature"]),
                   signature["protected"].encode("ascii") + b"." + canonicalize(verdict).encode())
    except Exception:  # noqa: BLE001 - uniform failure
        return "invalid_signature"
    exp = verdict.get("expires_at")
    now = now or datetime.now(timezone.utc)
    if isinstance(exp, str) and now.strftime("%Y-%m-%dT%H:%M:%SZ") > exp:
        return "expired"
    return "valid"


def main() -> None:  # `hs-verify verdict.json signature.json [jwks.json]`
    import sys
    v = json.load(open(sys.argv[1])); s = json.load(open(sys.argv[2]))
    j = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else None
    print(verify(v, s, jwks=j))
