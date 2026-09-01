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
