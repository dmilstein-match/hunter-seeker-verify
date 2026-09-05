# Changelog

## 0.2.0 — 2026-09-04
- **JWKS default moves to `https://hunter-seeker.io/.well-known/jwks.json`.** The service moved to
  the `.io` apex; `hunter-seeker.net` 308-redirects. This matters beyond tidiness: `urllib` did not
  follow 308 until CPython 3.11 (bpo-40321 landed two days after 3.10.0 shipped), and this package
  declares `requires-python = ">=3.10"` — so on its own floor, 0.1.0's `fetch_jwks()` raises
  `HTTPError: 308` rather than following. The TypeScript build uses `fetch`, which does follow.
- **0.1.0 installs cannot be repaired by this release.** They hold the old URL in compiled code and
  never re-read it. This fixes new installs only; the redirect is what keeps 0.1.0 working at all.
- CI now runs Python **3.10 and 3.12**. The 3.10 leg is the one that would have caught the above —
  the matrix was 3.12-only, so the failure was invisible to every gate.
- `vectors.json` is UNCHANGED and still reads `"issuer": "hunter-seeker.net"`. It is a real
  production Verdict and the signature covers that field; editing it to look consistent would
  forge the artifact the whole package exists to check.
- Security contact is now `security@hunter-seeker.io`.
- README status table corrected — it still claimed the packages were unpublished and the endpoints
  were not serving. Both were published at 0.1.0 and the endpoints are live.

## 0.1.0 — unreleased
- Python `hs-verify` and TypeScript `@hunter-seeker/verify`: keyless verification of Verdicts
  (Ed25519 detached JWS over RFC 8785 JCS), four-status output, shared test vectors.
- `vectors.json` is cut with a pre-release key; the `vectors-are-live` CI job turns required at 1.0.0.
- README: a Verdict without a signature is unverifiable by definition.
