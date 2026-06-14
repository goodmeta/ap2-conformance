# Conformance — methodology, coverage, and what's deferred

## Methodology

AP2's core verification step is *"verify and process the SD-JWT chain according to [Delegate SD-JWT]"* — and that draft's algorithm is not vendored in the AP2 repo. So the **authoritative, pinnable encoding of AP2's behaviour is its reference SDK**, which is also exactly what mints these vectors. Testing against the SDK is testing against AP2's *actual behaviour*, not a paraphrase.

- **Pin:** AP2 repo `google-agentic-commerce/AP2`, commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`.
- **Positive vectors** carry the per-hop payloads / violation strings / hashes AP2's SDK produces.
- **Negative `chain` vectors** are each **confirmed rejected by AP2's own verifier at mint time** — a true negative per AP2, not per our assumptions.
- **Canonical clock** `1780000000` for every time check (chain `iat`/`exp` and x509 validity), so runs are reproducible.

## Coverage by AP2 layer

The requirement IDs below are AP2's, extracted from `docs/ap2/*.md` at the pinned commit (`SPEC-*`, `AUTH-*`, `PAY-*`, `CHK-*`, `SEC-*`, `IMPL-*`).

| AP2 layer | Vector category | Key requirements exercised |
|---|---|---|
| Chain mechanics (Delegate SD-JWT) | `chain`, `hash-pairs` | canonical `~~` split; `parse_token` rules; ASCII binding-hash math (`sd_hash` / `issuer_jwt_hash` / disclosure digests); root ES256 verify; RFC-9901 disclosure unpack; KB hop `typ`; hop ES256 under prev `cnf.jwk`; exactly-one binding; 3-tier `cnf` resolution (strict EC P-256); terminal-MUST-NOT/intermediate-MUST carry `cnf`; `exp`/`iat`; full chain walk → per-hop payloads (AUTH-3/4/5/6/14/24, SPEC-10/11, IMPL-01/02) |
| Mandate semantics | `payment-constraints`, `checkout-constraints` | exact `vct` match incl. version; open→closed preset-claim preservation; closed-field requirements (SPEC-14/15/16/19/38/41, PAY-04..08, CHK-05/07) |
| Constraints (closed-world) | `payment-constraints`, `checkout-constraints` | **unknown ⇒ fail** (AUTH-15/SPEC-39); budget, amount_range, agent_recurrence, allowed_payees/payment_instruments/pisps, reference, execution_date; checkout allowed_merchants + line_items max-flow (SPEC-26..37, PAY-21..29, CHK-12/14/15) — **violation strings byte-exact vs AP2** |
| Linkage & receipts | `checkout-chain`, `receipt-reference` | `checkout_hash` = hash of `checkout_jwt`; `transaction_id` binding; receipt `reference` = `sd_hash` of the final SD-JWT (SPEC-4/5/6/9/19, AUTH-17/22, CHK-05/06) |
| Trust & algorithms | `chain` (x5c/kid) | root trust via `kid` lookup or `x5c` chain-to-trusted-root; EC P-256; ES256 (SPEC-2/23/46, AUTH-8/12/13) |

## Core vs hardening

| Profile | Count | Meaning |
|---|---:|---|
| **Core** | 62 | AP2's reference SDK agrees. A conformant verifier must pass all. |
| **Hardening** | 5 | Stricter than AP2 (AP2 accepts; a hardened verifier rejects). Informational. |

The 5 hardening checks: `x5c_fail_open` (no trusted roots configured → refuse, don't fail open), `x5c_expired` (cert outside validity), `x5c_non_ca_intermediate` (issuer lacks `CA:TRUE`), `x5c_wrong_curve_leaf` (leaf not P-256), and `cc_tampered_hash` (self-recompute `checkout_hash` instead of trusting the claim). AP2's SDK accepts all five; failing them means an implementation follows AP2's literal behaviour, which is **not** a conformance failure.

## What's deferred (honest)

These are not yet covered as vectors and are called out rather than silently omitted:

- **Disclosure-reorder negative** — a reordered ≥2-disclosure segment that breaks `sd_hash`. Currently covered indirectly by the binding-mismatch rejection and the byte-exact `sd_hash`-over-ordered-disclosures hash vector; a dedicated reorder vector is tracked.
- **x5c basic `keyUsage` / `pathLenConstraint`** — not asserted (the reference verifier relies on `CA:TRUE`; Node's `X509Certificate` doesn't expose basic KeyUsage). Bounded by the CA check.
- **Receipt *signing*** — out of scope. This suite covers mandate *verification* (the verifier side); issuing/signing receipts is the issuer side.
- **Cross-presentation budget accumulation** — the budget/recurrence vectors carry the accumulator as `context`; maintaining that state across presentations is the integrator's responsibility, not a single-vector check.

## Reproduce the vectors

See [`generators/README.md`](generators/README.md). In short: `pip install` AP2 at the pinned commit, run the generators against its SDK, and confirm each vector is accepted/rejected by AP2's own verifier (the generators assert this at mint time).
