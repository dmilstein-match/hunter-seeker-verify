# @hunter-seeker/verify

Keyless verification of a **Hunter-Seeker Verdict**, in TypeScript. Zero dependencies; uses
WebCrypto Ed25519. Node >= 18.

```ts
import { verify } from "@hunter-seeker/verify";
await verify(verdict, signature);            // fetches the published JWKS
await verify(verdict, signature, { jwks });  // fully offline
```

Returns exactly one of `valid`, `invalid_signature`, `expired`, `unknown_key`.

Ed25519 detached JWS (RFC 7797, `b64:false`) over RFC 8785 canonical JSON. The Python twin —
`hs-verify` on PyPI — tests against the same vectors, which is how the two are proven
interoperable byte for byte.

**Pre-release:** the hosted JWKS is not serving yet. Full status and trust model:
https://github.com/dmilstein-match/hunter-seeker-verify

Apache-2.0.
