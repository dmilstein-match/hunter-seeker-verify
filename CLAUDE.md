# hunter-seeker-verify — working rules

This repo is the **trust anchor**. It is the one artifact a reviewer with no account touches, and
the only thing standing behind the claim that an agent did not author its own score. Everything
below exists because that claim is worthless if the published library is not the library here.

## The one invariant

**What the registries serve must equal what this repo says.** Not the version alone — the
`JWKS_URL` too, and on the declared Python floor, not just the newest interpreter.

This was violated for months and nothing caught it. The repo read `0.2.0` and pointed at
`hunter-seeker.io`; PyPI and npm served `0.1.0` pointing at `hunter-seeker.net`, which
308-redirects — and `urllib` did not follow 308 until Python 3.11 while `pyproject.toml` declares
`requires-python = ">=3.10"`. So an auditor following the README on the floor got an unhandled
`HTTPError: 308` where they expected a verdict. Meanwhile the root README said "published", the two
READMEs that actually ship to the registries said "pre-release", and every CI job was green,
because every job built from the checkout.

## Gates — all four, every change

```
cd python && python -m pytest -q          # includes the shared cross-language vector tables
cd typescript && npm test
python scripts/check_live.py --vectors    # the committed vectors verify against the LIVE JWKS
```
and in CI, `registry-installs-clean` — which installs from PyPI and npm rather than the checkout
and asserts version + `JWKS_URL` against this repo, on Python **3.10**.

That last job is the only one that can see the failure described above. Do not make it
`continue-on-error` to get a build green: it is red exactly when the published artifact is wrong,
which is the one thing this repo exists to prevent.

## Anchors — never edited to make a build pass

- **`vectors.json`** is a conformance anchor. The signed `payload` / `canonical` / `signature`
  triple is cut by the engine's release process; if canonicalization changes, the LIBRARIES are
  wrong, not the vector.
- The `canonical_only` and `expiry` blocks carry no signature on purpose, because neither rule is
  reachable from a signed payload: the signed one's largest number is `1`, and expiry is checked
  *after* the signature, so varying `expires_at` there only ever returns `invalid_signature`. Both
  suites drive those two tables. **Adding a case is correct; changing an expected value to match
  the code is not** — that is how the two implementations drifted apart in the first place.
- The **historical `kid` list** in `.github/workflows/ci.yml` only ever grows. Retired keys stay
  published so old Verdicts keep verifying; removing a kid to make a job pass silently breaks
  every Verdict signed with it.

## Two rules that decide arguments before they start

1. **RFC 8785 says a JSON number is an ES6 double.** Where the two languages disagree, the
   TypeScript side is conformant by construction and Python is the one to fix. Python's `_n` is a
   full `Number::toString` implementation for that reason, verified differentially against node
   over several thousand values — including 4,000 random 64-bit patterns. Re-verify that way if you
   touch it; a plausible-looking simplification (`str(int(x))`, or coercing to float and stopping)
   disagrees above 2^53.
2. **Times are compared as instants, never as strings.** `"…+00:00"` sorts before `"…Z"`, so a
   lexicographic expiry check reads an offset-form timestamp as unexpired for the rest of the
   century. Both libraries expose `expired_at` / `expiredAt` so the rule is testable on its own.

## Publishing

`publish.yml` fires **only** on a `v*` tag. `workflow_dispatch` cannot publish — its
`versions-agree` guard compares `GITHUB_REF_NAME` to the version in `pyproject.toml`, so a branch
name fails it. If a release did not happen, the reason is almost always that no tag was pushed.

Order matters: **release first, then land the registry gate.** The gate is correctly red until the
published artifact catches up, and a gate that is red for a true reason still teaches people to
ignore red.
