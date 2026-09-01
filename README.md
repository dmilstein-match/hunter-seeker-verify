# hunter-seeker-verify

> ### Status: pre-release
>
> The code here is complete and tested; the hosted service it talks to is not live yet.
> Concretely, **today**:
>
> | Thing the docs below tell you to use | Reality today |
> |---|---|
> | `pip install hs-verify` / `npm install @hunter-seeker/verify` | not on PyPI / npm yet — install from this repo |
> | `pip install hunter-seeker` | not on PyPI yet — install from this repo |
> | `https://hunter-seeker.net/api/mcp` and `/.well-known/jwks.json` | not serving yet |
> | `vectors.json` | signed with a **pre-release test key**, not the production one. Run `python scripts/check_live.py --vectors` and it will say so |
>
> Everything offline works now: both verifiers agree byte for byte on the shared vectors, and
> the canonical form and the signature check are the ones production will use. What is waiting
> is the engine deploy that publishes the JWKS and re-cuts the vectors with the live key.
>
> This notice comes down when the JWKS is live and the packages are published.


Keyless verification of a **Hunter-Seeker Verdict** — the signed decision an AI agent receives
when it asks Hunter-Seeker who to act on and why. No account, no API key, no call to
Hunter-Seeker beyond fetching the public keys.

A Verdict is signed by the engine that computed it (Ed25519, detached JWS per RFC 7797) over
its RFC 8785 canonical JSON. This repo lets anyone — an approver, an auditor, another vendor's
agent — check that a Verdict is authentic and unaltered.

```
valid | invalid_signature | expired | unknown_key
```

Those four words are the whole output, by design: the verifier is not an oracle.

## Python

```bash
pip install hs-verify
```
```python
from hs_verify import verify
verify(verdict, signature)              # fetches https://hunter-seeker.net/.well-known/jwks.json
verify(verdict, signature, jwks=jwks)   # offline
```
```bash
hs-verify verdict.json signature.json [jwks.json]
```

## TypeScript / Node ≥ 18

```bash
npm install @hunter-seeker/verify
```
```ts
import { verify } from "@hunter-seeker/verify";
await verify(verdict, signature);                 // fetches the JWKS
await verify(verdict, signature, { jwks });       // offline
```
Zero dependencies; uses WebCrypto Ed25519.

## What is verified

1. The signature header is `alg: EdDSA`, `b64: false` (detached), with a `kid`.
2. The `kid` is in the JWKS. Retired keys stay published, so old Verdicts keep verifying.
3. The Ed25519 signature over `protected || "." || JCS(verdict)` is valid.
4. `expires_at` has not passed. An expired Verdict is **re-scored, never reused**.

A Verdict with no signature is unverifiable: production servers always sign, so treat a missing
signature as `invalid_signature`, never as a valid decision.

Pass the verdict as the object you received. The library canonicalises it (RFC 8785); do not
re-serialise it yourself first.

## Test vectors

`vectors.json` holds a payload, its canonical form, a signature, a JWKS, and a tampered copy.
Both libraries test against the same file, which is how they are proven interoperable:

```bash
(cd python && python -m pytest -q)
(cd typescript && npm test)
```

The vectors are cut by the engine's release process. **The ones committed today are from a
pre-release build, signed with a test key** — they prove the two libraries agree byte for byte,
which is what they are for, but they are not a production artifact. They are re-cut with the
live signing key when the engine publishes its JWKS. `python scripts/check_live.py --vectors`
compares the vector `kid` against the live JWKS and tells you which you are holding.

## Trust model

- The private key lives only in the engine service. Nothing above the engine can sign.
- Keys rotate every 90 days; retired public keys remain in the JWKS.
- This library verifies authenticity and integrity. It does not, and cannot, tell you whether
  the decision was *right* — that is what the Verdict's own trust block and the human gate are for.

## Security

Report issues to security@hunter-seeker.net. Please do not open public issues for
signature-bypass reports.

Apache-2.0.
