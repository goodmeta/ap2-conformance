# HTTP conformance contract

How to make an AP2 verifier **testable over HTTP** so the live runner (and the
[microsite](site/)) can point at it. This contract covers the **`chain`
category** — the dSD-JWT verification core. The remaining categories (payment /
checkout constraints, linkage, hash-pairs) are lower-level inputs (payloads,
segments), not whole chains, so they run in-process via the
[`Ap2VerifierAdapter`](src/adapter.ts), not over HTTP.

## The endpoint

A single `POST` endpoint that verifies one chain.

**Request** — `Content-Type: application/json`:

```jsonc
{
  "chain": "<compact dSD-JWT, ~~-joined>",
  "rootKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "..." },  // OR null
  "trustedRoots": ["<base64url-DER cert>", "..."],   // OR null  (x5c trust path)
  "currentTimeUnix": 1780000000,                     // evaluation clock (seconds)
  "expectedAud": "<merchant audience>",
  "expectedNonce": "<merchant nonce>"
}
```

Exactly one of `rootKey` / `trustedRoots` is non-null:
- `rootKey` → trust this public JWK as the root signer (the `kid`/direct path).
- `trustedRoots` → trust the root header's `x5c` chain if it anchors to one of these root CAs (base64url-DER). An empty array means "no roots configured" — a hardened verifier refuses rather than failing open.

Passing the trust anchor in the request is deliberate: it isolates the
**verification logic** (signatures, `cnf` chaining, binding, `aud`/`nonce`, alg
pinning, x5c chain validation) from key-distribution config. That's what's being
conformance-tested.

**Response** — always HTTP `200`, the verdict in the body:

```jsonc
// accepted:
{ "ok": true,  "payloads": [ { /* open */ }, /* … */, { /* closed */ } ] }
// rejected:
{ "ok": false, "error": "human-readable reason" }
```

For a `valid` vector, the runner checks `ok === true` **and** that `payloads`
deep-equals the vector's `expectedPayloads`. For a `reject` vector, it checks
`ok === false`.

## CORS

If you want browsers to call your endpoint directly, send
`Access-Control-Allow-Origin`. Not required when tested through the runner's
server-side proxy (`/api/conform?target=<your-url>`), which is how the microsite
tests arbitrary URLs.

## Reference implementation

[`api/verify-chain.ts`](api/verify-chain.ts) implements this contract on top of
`@goodmeta/agent-verifier`. The microsite prefills the URL field with it, so
"Run" shows a live green result you can reproduce — then swap in your own URL.

## What "pass" means

Reproducing the per-vector accept/reject of AP2's reference SDK for the chain
category. It is **not** an official AP2/FIDO certification.
