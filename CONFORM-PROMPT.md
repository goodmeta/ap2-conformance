# Make your AP2 verifier conformance-testable

Want the public runner to test *your* AP2 verifier? Add one small endpoint. The
fastest way: paste the prompt below into your coding agent (Claude Code, Cursor,
etc.). It wires a keyless `/conform/verify-chain` endpoint to your existing
verifier, implementing the [conformance HTTP contract](CONTRACT.md).

---

## Paste this to your agent

> Add an HTTP endpoint that makes our AP2 mandate verifier testable by the open AP2 conformance suite (github.com/goodmeta/ap2-conformance).
>
> **Endpoint:** `POST /conform/verify-chain`
> - **Keyless** (no auth) and **CORS-open** (`Access-Control-Allow-Origin: *`; answer `OPTIONS` preflight with `204`).
> - **Stateless:** it must NOT touch our database, budget ledger, or trusted-key store. It trusts ONLY the key supplied in the request and evaluates at the request's clock. Keep it isolated from our auth/state.
>
> **Request JSON:**
> ```jsonc
> {
>   "chain": "<compact dSD-JWT, ~~-joined>",
>   "rootKey": { /* EC P-256 public JWK */ } | null,   // trust this key as the root signer (kid/direct path)
>   "trustedRoots": ["<base64url-DER cert>", "..."] | null,  // OR: accept the root header's x5c chain if it anchors to one of these CAs
>   "currentTimeUnix": 1780000000,   // evaluation clock (seconds) — use for iat/exp AND x509 validity
>   "expectedAud": "<merchant audience>",
>   "expectedNonce": "<merchant nonce>"
> }
> ```
> Exactly one of `rootKey` / `trustedRoots` is non-null. An empty `trustedRoots` array means "no roots configured" — refuse rather than fail open.
>
> **Behaviour:** run our EXISTING AP2 chain verification with that trust anchor and clock — do not invent new verification logic, wire to the verifier we already have. Always respond HTTP `200`; put the verdict in the body:
> - accepted → `{ "ok": true, "payloads": [ /* per-hop effective payloads, open … closed */ ] }`
> - rejected → `{ "ok": false, "error": "<reason>" }`

---

## Then test it

1. Deploy your service.
2. Open **https://ap2-conformance.vercel.app**, paste `https://your-service/conform/verify-chain` into the URL field, and hit **Run conformance**.
3. You get a live per-vector pass/fail for the **chain** category. For the full 67-check suite (constraints, linkage, hash-pairs), use the in-process adapter — see the [README](README.md).

## Reference implementations

- [`api/verify-chain.ts`](api/verify-chain.ts) — the bundled reference (Node/Vercel).
- `agent-verifier-pro` ships the same endpoint at `/conform/verify-chain`.

Both wrap [`@goodmeta/agent-verifier`](https://www.npmjs.com/package/@goodmeta/agent-verifier). Yours wraps whatever engine you built — that's the point.
