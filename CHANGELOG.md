# Changelog

## 0.1.0 — unreleased
- Python `hs-verify` and TypeScript `@hunter-seeker/verify`: keyless verification of Verdicts
  (Ed25519 detached JWS over RFC 8785 JCS), four-status output, shared test vectors.
- `vectors.json` is cut with a pre-release key; the `vectors-are-live` CI job turns required at 1.0.0.
- README: a Verdict without a signature is unverifiable by definition.
