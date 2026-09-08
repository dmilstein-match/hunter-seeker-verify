# hs-verify

Keyless verification of a **Hunter-Seeker Verdict** — the signed decision an AI agent receives
when it asks Hunter-Seeker who to act on and why. No account, no API key, no call to
Hunter-Seeker beyond fetching the public keys.

```python
from hs_verify import verify
verify(verdict, signature)              # fetches the published JWKS
verify(verdict, signature, jwks=jwks)   # fully offline
```
```bash
hs-verify verdict.json signature.json [jwks.json]
```

Returns exactly one of `valid`, `invalid_signature`, `expired`, `unknown_key`. The verifier is
not an oracle: those four words are the whole output.

A Verdict with no signature is unverifiable and reports `invalid_signature`, never `valid`.

Ed25519 detached JWS (RFC 7797, `b64:false`) over RFC 8785 canonical JSON. The TypeScript
twin — `@hunter-seeker/verify` — tests against the same vectors, which is how the two are
proven interoperable.

**Key rotation and caching.** Keys rotate every 90 days and **retired public keys stay published**,
so a Verdict signed two quarters ago still verifies. Each signature names its `kid`; match on that
rather than assuming one key. For offline or air-gapped verification, cache the JWKS and pin the
`kid` you need — `fetch_jwks(url)` takes an explicit URL and `HS_JWKS_URL` overrides the default,
so a local copy is a one-line change. Refresh the cache when you meet an unknown `kid`, not on a
timer.

Full status, trust model and vectors:
https://github.com/dmilstein-match/hunter-seeker-verify

Apache-2.0.
