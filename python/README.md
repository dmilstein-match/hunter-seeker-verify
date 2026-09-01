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

**Pre-release:** the hosted JWKS is not serving yet and the committed test vectors are signed
with a pre-release key. Full status, trust model and vectors:
https://github.com/dmilstein-match/hunter-seeker-verify

Apache-2.0.
