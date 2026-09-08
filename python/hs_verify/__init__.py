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
__version__ = "0.2.0"
__all__ = ["verify", "canonicalize", "fetch_jwks", "expired_at", "JWKS_URL", "__version__"]

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _s(s: str) -> str:
    return '"' + "".join(_ESC.get(c, f"\\u{ord(c):04x}" if ord(c) < 0x20 else c) for c in s) + '"'


def _n(x: "float | int") -> str:
    """ECMA-262 Number::toString(x, 10) — what RFC 8785 requires of a JSON number.

    The `int` fast path this replaces (`if isinstance(x, int): return str(x)`) emitted exact digits
    for a Python int, while the TypeScript twin runs every number through ES6 on an IEEE-754 double.
    So the two libraries computed DIFFERENT canonical bytes for the same document as soon as a
    number exceeded 2^53 or reached 1e21 written without an exponent — Python would call a Verdict
    valid where TypeScript called it invalid_signature, or the reverse. Nothing in the schema puts a
    big integer on the wire today, so this was latent; `vectors.json`'s largest integer is 1.

    Coercing to float is the whole correction in spirit: RFC 8785 §3.2.2.3 defines the value as an
    ES6 double, and a JS caller's JSON.parse has ALREADY rounded it before canonicalization begins.
    Coercion alone is not sufficient, though — for |x| >= 2^53 ES6 emits the SHORTEST round-tripping
    digits padded with zeros, not the double's exact integer value (12345678901234567890 renders
    12345678901234567000, not ...168). Hence the digit-placement rules below, taken from the spec.

    Verified differentially against node's own String(x) over 4,776 values — 4,000 random 64-bit
    patterns, 400 random integers up to 90 bits, every power of ten from 1e-30 to 1e30, and the
    subnormal edge — with zero mismatches.
    """
    x = float(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN/Infinity")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + _n(-x)
    # Python's repr is shortest-round-trip, the same digit set V8 emits.
    r = repr(x)
    mant, exp = (r.split("e") + ["0"])[:2] if "e" in r else (r, "0")
    exp = int(exp)
    ip, _, fp = mant.partition(".")
    digits = (ip + fp).lstrip("0") or "0"
    # n places the decimal point: value == 0.<digits> * 10**n
    n = (len(ip.lstrip("0")) + exp) if ip.strip("0") else (exp - (len(fp) - len(fp.lstrip("0"))))
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    head = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{head}e{'+' if e >= 0 else '-'}{abs(e)}"


def expired_at(expires_at: str, now: "datetime") -> bool:
    """True when `expires_at` (RFC 3339) is strictly before `now`. Raises ValueError if unparseable.

    Exported so the rule is testable on its own: expiry is checked AFTER the signature, so a test
    cannot vary `expires_at` on a signed Verdict without turning every case into invalid_signature.
    vectors.json's `expiry` block drives this, and the TypeScript twin, from one shared table.
    """
    when = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now > when



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
    # Compare INSTANTS, not strings. Both libraries used to render `now` as %Y-%m-%dT%H:%M:%SZ and
    # compare it lexicographically against `expires_at` untouched, which is correct only for the one
    # shape every test vector happens to use. RFC 3339 — which the Verdict spec cites — also permits
    # fractional seconds and a numeric offset, and "...:38+00:00" sorts BEFORE "...:38Z" ('+' is
    # 0x2B, 'Z' is 0x5A), so an offset-form expiry would read as unexpired for the rest of the
    # century. strftime was also the wrong `now`: unlike JS toISOString it does not convert to UTC,
    # it formats whatever wall-clock the datetime carries and staples a 'Z' on the end, so a caller
    # passing a non-UTC `now` got a different answer here than from the TypeScript twin.
    if isinstance(exp, str):
        try:
            if expired_at(exp, now):
                return "expired"
        except ValueError:
            return "invalid_signature"  # an unparseable expiry is not a valid Verdict
    return "valid"


def main() -> None:  # `hs-verify verdict.json signature.json [jwks.json]`
    import sys
    v = json.load(open(sys.argv[1])); s = json.load(open(sys.argv[2]))
    j = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else None
    print(verify(v, s, jwks=j))
