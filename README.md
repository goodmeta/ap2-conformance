# AP2 Conformance Harness

An open, implementation-agnostic conformance suite for **AP2** (the [Agent Payments Protocol](https://github.com/google-agentic-commerce/AP2)) mandate-verification layer — the dSD-JWT delegation chain, its constraints, linkage, and receipt reference.

The vectors are **minted from AP2's own reference SDK** (pinned at commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`), so a passing run means your verifier matches the reference implementation's *actual behaviour* — not one more reading of the spec. Point your verifier at it and find out where you diverge.

```
$ npm run conformance

  ✓ chain                  19/19 core · 4/4 hardening
  ✓ payment-constraints    24/24 core
  ✓ checkout-constraints   11/11 core
  ✓ checkout-chain         2/2 core · 1/1 hardening
  ✓ receipt-reference      4/4 core
  ✓ hash-pairs             2/2 core

CORE:      62/62  (must be 100% to be conformant)
HARDENING: 5/5  (optional, stricter-than-AP2)

✅ CONFORMANT — all core vectors pass
```

## What this is — and isn't

It **is** an open set of golden vectors plus a runner you can point any AP2 verifier at, with a documented vector schema ([VECTORS.md](VECTORS.md)) so an implementation in any language can consume the same JSON.

It is **not** an official AP2 or FIDO certification. AP2 was donated to the FIDO Alliance, which owns any future certification program. "Conformant" here means precisely *"reproduces the per-vector behaviour of AP2's reference SDK at the pinned commit"* — a useful, verifiable signal, not an endorsed seal.

## Two profiles: core vs hardening

This distinction is the point of a *neutral* suite — and where naive conformance tests go wrong.

- **CORE** — behaviour where AP2's own reference SDK agrees. A conformant AP2 verifier **must** pass all of these.
- **HARDENING** — cases where the reference verifier is deliberately **stricter than AP2**: AP2 *accepts* them, a hardened verifier *rejects* them (e.g. x5c with no trusted roots configured, an expired certificate, a self-recomputed `checkout_hash`). These are **informational**. A verifier that follows AP2's literal behaviour will "miss" them, and that is **not** a conformance failure.

A suite that lumped these together would wrongly fail a spec-faithful implementation for one vendor's opinions. They are reported, and counted, separately.

## Coverage

| Category | Core | Hardening | What it exercises |
|---|---:|---:|---|
| `chain` | 19 | 4 | dSD-JWT chain walk: root + KB-SD-JWT hops, `cnf` chaining, exactly-one binding (`sd_hash`/`issuer_jwt_hash`), terminal `aud`/`nonce`, ES256, x5c/kid trust |
| `payment-constraints` | 24 | — | All payment constraint evaluators (budget, amount range, recurrence, allowed payees/instruments/PISPs, reference, execution date); unknown-constraint fail-closed; violation strings byte-exact vs AP2 |
| `checkout-constraints` | 11 | — | Checkout constraints incl. `line_items` bipartite max-flow; `allowed_merchants` |
| `checkout-chain` | 2 | 1 | Checkout→payment linkage; self-computed `checkout_hash` (hardening) |
| `receipt-reference` | 4 | — | Mandate Receipt `reference` = `sd_hash` of the final SD-JWT segment (AUTH-17) |
| `hash-pairs` | 2 | — | Per-segment canonicalization + binding-hash math, byte-exact |
| **Total** | **62** | **5** | |

Every negative vector in `chain` is **confirmed rejected by AP2's own verifier at mint time**, so it is a true negative per AP2 — not merely per our assumptions. See [CONFORMANCE.md](CONFORMANCE.md) for the AP2 requirement → vector traceability and the honest list of what is deferred.

## Run it

```bash
npm install
npm run conformance     # runs the reference adapter; exits non-zero on any core failure
```

The reference adapter is backed by [`@goodmeta/agent-verifier`](https://www.npmjs.com/package/@goodmeta/agent-verifier), a byte-exact port of AP2's reference SDK.

## Point your own verifier at it

Implement the [`Ap2VerifierAdapter`](src/adapter.ts) interface (six small methods — verify a chain, evaluate payment/checkout constraints, verify a checkout chain, compute a receipt reference, and optionally per-segment hashes) and run:

```ts
import { runConformance, type Ap2VerifierAdapter } from "@goodmeta/ap2-conformance";

const myAdapter: Ap2VerifierAdapter = { /* wire to your verifier */ };
const report = await runConformance(myAdapter);
console.log(report.core);       // { passed, total } — must be 100% to be conformant
console.log(report.hardening);  // optional stricter-than-AP2 checks
process.exit(report.conformant ? 0 : 1);
```

In another language? The vectors are plain JSON. [VECTORS.md](VECTORS.md) documents the schema, how to drive each category, the canonical evaluation clock, and the two quirks you need to handle (the base64url-DER x5c encoding and the two `repr`-bearing AP2 violation messages).

## Make your verifier testable over HTTP

Expose one endpoint matching [CONTRACT.md](CONTRACT.md) and the live runner can test your verifier at its URL (chain category). Fastest path: paste [CONFORM-PROMPT.md](CONFORM-PROMPT.md) into your coding agent — it wires a keyless `/conform/verify-chain` to your existing verifier.

## Provenance & reproducibility

- **Vectors:** minted by AP2's reference SDK at commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`. See [`generators/`](generators/) to regenerate them yourself.
- **Canonical clock:** the suite evaluates at a fixed instant (`1780000000`, the SDK clock the vectors were minted at), so results don't depend on wall-clock time.
- **No network, no secrets.** Pure local verification.

## Layout

```
vectors/         golden vectors (JSON) — the product; schema in VECTORS.md
generators/      Python scripts that mint the vectors from AP2's own SDK
src/             the runner + the Ap2VerifierAdapter interface + reference adapter
CONFORMANCE.md   AP2 requirement → vector traceability + honest deferrals
VECTORS.md       the vector schema (for non-TS implementers)
GLOSSARY.md      decoder ring for the dSD-JWT chain (SD-JWT, cnf, kid, x5c, …)
```

## License

[Apache-2.0](LICENSE) — matching AP2's own license. The vectors are derived from AP2's reference SDK (Apache-2.0); see [NOTICE](NOTICE).
