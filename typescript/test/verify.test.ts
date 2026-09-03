import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalize, verify } from "../src/index.ts";

const VEC = JSON.parse(readFileSync(new URL("../../vectors.json", import.meta.url), "utf8"));

test("canonical form matches the engine's", () => {
  assert.equal(canonicalize(VEC.payload), VEC.canonical);
});

test("valid / tampered / unknown key / expired", async () => {
  assert.equal(await verify(VEC.payload, VEC.signature, { jwks: VEC.jwks }), "valid");
  assert.equal(await verify(VEC.tampered, VEC.signature, { jwks: VEC.jwks }), "invalid_signature");
  assert.equal(await verify(VEC.payload, VEC.signature, { jwks: { keys: [] } }), "unknown_key");
  assert.equal(await verify(VEC.payload, VEC.signature, { jwks: VEC.jwks, now: new Date("2100-01-01T00:00:00Z") }), "expired");
});

// The vectors above are synthetic on purpose — they carry the canonicalisation edge cases. This
// one is a REAL Verdict emitted by production and signed by the production key, which is the
// claim the library exists to support: anyone can check a decision, with no account and no
// server. Its `valid` check is pinned to verify_at because a real Verdict has a real
// expires_at; an unpinned assertion would turn this suite red on that date for no reason but
// the calendar.
test("a real production verdict verifies offline", async () => {
  const live = VEC.live;
  const at = new Date(live.verify_at);
  assert.equal(await verify(live.verdict, live.signature, { jwks: VEC.jwks, now: at }), live.expected.valid);
  const after = new Date(live.verdict.expires_at);
  after.setFullYear(after.getFullYear() + 1);
  assert.equal(await verify(live.verdict, live.signature, { jwks: VEC.jwks, now: after }), live.expected.expired_after_window);
  assert.equal(await verify(live.verdict, live.signature, { jwks: { keys: [] }, now: at }), "unknown_key");
});

test("the real verdict is signed by the key we publish", () => {
  // vectors.json ships its own copy of the JWKS. If that copy ever drifts from the kid the
  // signature names, the test above would pass against a stale copy while every real reviewer
  // failed. scripts/check_live.py --vectors is the online half of this check.
  const kids = new Set(VEC.jwks.keys.map((k: { kid: string }) => k.kid));
  assert.ok(kids.has(VEC.live.signature.kid));
});
