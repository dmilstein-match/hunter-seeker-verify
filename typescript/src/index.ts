/**
 * @hunter-seeker/verify — keyless verification of a Hunter-Seeker Verdict.
 *
 *   import { verify } from "@hunter-seeker/verify";
 *   const status = await verify(verdict, signature);          // fetches published JWKS
 *   const status = await verify(verdict, signature, { jwks }); // offline
 *
 * Returns exactly one of "valid" | "invalid_signature" | "expired" | "unknown_key".
 * Node 18+ (WebCrypto Ed25519). Zero dependencies.
 */
import { webcrypto } from "node:crypto";

export const JWKS_URL = "https://hunter-seeker.net/.well-known/jwks.json";
export type Status = "valid" | "invalid_signature" | "expired" | "unknown_key";
export type Jwks = { keys: Array<{ kid: string; kty: string; crv: string; x: string; alg?: string }> };
export type Signature = { protected: string; signature: string; kid?: string };

const ESC: Record<string, string> = { '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };

function str(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    out += ESC[ch] ?? (c < 0x20 ? "\\u" + c.toString(16).padStart(4, "0") : ch);
  }
  return out + '"';
}

function num(x: number): string {
  if (!Number.isFinite(x)) throw new Error("NaN/Infinity");
  if (x === 0) return "0";
  return String(x); // ES6 Number#toString is what RFC 8785 specifies
}

/** RFC 8785 JSON Canonicalization Scheme. */
export function canonicalize(v: unknown): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return num(v);
  if (typeof v === "string") return str(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort((a, b) => {
      // sort by UTF-16 code units — JS string comparison already does this
      return a < b ? -1 : a > b ? 1 : 0;
    });
    return "{" + keys.map((k) => str(k) + ":" + canonicalize(o[k])).join(",") + "}";
  }
  throw new Error("not JSON: " + typeof v);
}

function b64u(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return new Uint8Array(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64"));
}

export async function fetchJwks(url = JWKS_URL): Promise<Jwks> {
  const r = await fetch(url);
  if (!r.ok) throw new Error("jwks fetch failed: " + r.status);
  return (await r.json()) as Jwks;
}

export async function verify(
  verdict: Record<string, unknown>,
  signature: Signature,
  opts: { jwks?: Jwks; now?: Date } = {},
): Promise<Status> {
  // OUTSIDE the try, and matching hs_verify. A JWKS that cannot be fetched is a transport
  // failure, not a verification result: swallowing it into the uniform "invalid_signature"
  // below tells the caller a genuine Verdict was FORGED because their network was down — the
  // one error that makes an auditor reject a real decision. The four-word contract says what
  // the verifier concluded about the Verdict; it has no word for "I could not reach the keys",
  // so that stays a thrown error the caller can see.
  const jwks = opts.jwks ?? (await fetchJwks());
  let kid: string | undefined;
  try {
    const header = JSON.parse(Buffer.from(b64u(signature.protected)).toString("utf8"));
    if (header.alg !== "EdDSA" || header.b64 !== false) return "invalid_signature";
    kid = header.kid;
    const key = jwks.keys.find((k) => k.kid === kid);
    if (!key) return "unknown_key";
    const pub = await webcrypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: key.x }, { name: "Ed25519" }, false, ["verify"]);
    const input = Buffer.concat([Buffer.from(signature.protected, "ascii"), Buffer.from("."), Buffer.from(canonicalize(verdict), "utf8")]);
    const ok = await webcrypto.subtle.verify({ name: "Ed25519" }, pub, b64u(signature.signature), input);
    if (!ok) return "invalid_signature";
  } catch {
    return "invalid_signature";
  }
  const exp = verdict["expires_at"];
  const now = (opts.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, "Z");
  if (typeof exp === "string" && now > exp) return "expired";
  return "valid";
}
