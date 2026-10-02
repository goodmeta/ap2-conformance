# Conformance — methodology, coverage, and what's deferred

## Methodology

AP2's core verification step is *"verify and process the SD-JWT chain according to [Delegate SD-JWT]"* — and that draft's algorithm is not vendored in the AP2 repo. So the **authoritative, pinnable encoding of AP2's behaviour is its reference SDK**, which is also exactly what mints these vectors. Testing against the SDK is testing against AP2's *actual behaviour*, not a paraphrase.

- **Pin:** AP2 repo `google-agentic-commerce/AP2`, commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`. That commit is after the v0.2 release (`b4587ac`, PR #233), so this suite targets **AP2 v0.2** (Checkout + Payment Mandates, open/closed). AP2 v0.1's Intent / Cart mandates are not tested; they no longer exist in the spec.
- **Positive vectors** carry the per-hop payloads / violation strings / hashes AP2's SDK produces.
- **Core negative vectors** are each **confirmed rejected by AP2's own SDK at mint time** — a true negative per AP2, not per our assumptions. Hardening negatives are the opposite by definition: the generators assert AP2's SDK *accepts* them (see [Core vs hardening](#core-vs-hardening)). The `mandate-semantics` and `receipts` vectors record AP2's outcome alongside each one (`ap2Outcome` / `ap2Result`).
- **Canonical clock** `1780000000` for every time check (chain `iat`/`exp` and x509 validity), so runs are reproducible.

## Coverage by AP2 layer

Spec citations are to `docs/ap2/*.md` and `code/sdk/schemas/ap2/*.json` at the pinned commit. The `SPEC-*` / `AUTH-*` / `PAY-*` / `CHK-*` / `IMPL-*` IDs are **Good Meta's own** per-document numbering from the requirement extraction in [`agent-verifier/AP2-AUDIT.md`](https://github.com/goodmeta/agent-verifier/blob/main/AP2-AUDIT.md); AP2's documents do not number their requirements. Every `mandate-semantics` and `receipts` vector also carries its own `cite` field.

| AP2 layer | Vector category | Key requirements exercised | Spec |
|---|---|---|---|
| Chain mechanics (Delegate SD-JWT) | `chain`, `hash-pairs` | canonical `~~` split; `parse_token` rules; ASCII binding-hash math (`sd_hash` / `issuer_jwt_hash` / disclosure digests); root ES256 verify; RFC-9901 disclosure unpack; KB hop `typ`; hop ES256 under prev `cnf.jwk`; exactly-one binding; 3-tier `cnf` resolution (strict EC P-256); terminal-MUST-NOT/intermediate-MUST carry `cnf`; `exp`/`iat`; full chain walk → per-hop payloads (AUTH-3/4/5/6/14/24, SPEC-10/11, IMPL-01/02) | `agent_authorization.md` §Verification and Processing Rules step 1, §Mandate Structure |
| Mandate type | `mandate-semantics` | exact `vct` match incl. version suffix, open and closed, payment and checkout; unknown constraint types fail evaluation (incl. an rDNS-named extension); closed mandates carry their required fields | `specification.md` §Mandate Versioning; `payment_mandate.md` §Type; `checkout_mandate.md` §Type; `agent_authorization.md` §Mandates using SD-JWT VCs, §Verification and Processing Rules step 3; `payment_mandate.json` / `checkout_mandate.json` `#/required` |
| Mandate semantics | `payment-constraints` | open→closed preset-claim preservation (SPEC-38/41, PAY-04..08) | `agent_authorization.md` §Verification and Processing Rules step 2 |
| Constraints (closed-world) | `payment-constraints`, `checkout-constraints` | budget, amount_range, agent_recurrence, allowed_payees/payment_instruments/pisps, reference, execution_date; checkout allowed_merchants + line_items max-flow (SPEC-26..37, PAY-21..29, CHK-12/14/15) — **violation strings byte-exact vs AP2** | `payment_mandate.md` §Payment Mandate Constraints; `checkout_mandate.md` §Constraints |
| Linkage | `checkout-chain`, `receipt-reference` | checkout constraints through the chain; receipt `reference` = `sd_hash` of the final SD-JWT (SPEC-4/5/6/9/19, AUTH-17/22, CHK-05/06) | `checkout_mandate.md` §Mandate Schema; `agent_authorization.md` §Action Authorization |
| Signed receipts | `receipts` | ES256 receipt verifies under the issuer key; wrong key / tampered payload rejected; schema-required fields (incl. the Success / Error branches); Checkout and Payment Receipt `reference` MUST match the hash of the closed mandate presented | `specification.md` §Checkout Mandate, §Payment Mandate, §Verification > Dispute; `agent_authorization.md` §Action Authorization; `payment_receipt.json`, `checkout_receipt.json` |
| Trust & algorithms | `chain` (x5c/kid) | root trust via `kid` lookup or `x5c` chain-to-trusted-root; EC P-256; ES256 (SPEC-2/23/46, AUTH-8/12/13) | SDK only: `code/sdk/python/ap2/sdk/sdjwt/chain.py` (`X5cOrKidPublicKeyProvider`); the `docs/ap2/*.md` prose does not specify `x5c` |

## Core vs hardening

| Profile | Meaning |
|---|---|
| **Core** | AP2's reference SDK agrees. A conformant verifier must pass all. |
| **Hardening** | Stricter than AP2's SDK (AP2 accepts; a hardened verifier rejects). Informational. |

The hardening checks:

- `x5c_fail_open` (no trusted roots configured → refuse, don't fail open), `x5c_expired` (cert outside validity), `x5c_non_ca_intermediate` (issuer lacks `CA:TRUE`), `x5c_wrong_curve_leaf` (leaf not P-256).
- `cc_tampered_hash` — self-recompute `checkout_hash` instead of trusting the claim. **The spec text requires this of the Merchant and at dispute time** (`specification.md` §Verification > Merchant: *"Verify that the hash of the Checkout JWT sent for approval matches the value included for the `checkout_hash` claim"*; §Verification > Dispute: *"The hash of the `checkout_jwt` MUST be independently computed from the included `checkout_jwt`"*). It stays in the hardening profile because AP2's SDK `CheckoutMandateChain.verify` only compares against an `expected_checkout_hash` the caller supplies and accepts this vector as given.
- `*_absent_required` (payment-constraints) — see [VECTORS.md](VECTORS.md#the-absence-class-_absent_).
- `payment_closed_missing_vct`, `checkout_closed_missing_vct` (mandate-semantics) — `vct` is **REQUIRED** (`agent_authorization.md` §Mandates using SD-JWT VCs; `#/required` in both closed schemas), but AP2's SDK fills it from a pydantic model default and accepts.

Failing a hardening check means an implementation follows AP2's SDK behaviour, which is **not** a conformance failure.

## Where the spec and AP2's SDK disagree (not encoded as core)

- **Receipt status field.** `agent_authorization.md` §Action Authorization defines the Mandate Receipt with `result` ∈ {`success`, `error`}. The receipt schemas (`payment_receipt.json`, `checkout_receipt.json` → `types/receipt_status.json`) and the SDK use `status` ∈ {`Success`, `Error`}. The `receipts` vectors follow the schemas and SDK.
- **Open Checkout Mandate needs a `line_items` constraint?** `open_checkout_mandate.json` has `"contains": {"$ref": "#/$defs/line_items"}`; neither `checkout_mandate.md` nor the SDK requires it (the SDK accepts an open checkout mandate with only `allowed_merchants`). Not tested either way.
- **Are open-mandate `constraints` optional?** `agent_authorization.md` §Mandates using SD-JWT VCs marks `constraints` OPTIONAL; both open schemas list it in `required`, and the SDK rejects its absence. Not tested either way.
- **Schema `vct` descriptions are stale.** Each mandate schema's `vct.description` says e.g. *"MUST be 'mandate.payment'"* while its `const` is `mandate.payment.1`. The prose (§Type sections, §Mandate Versioning) and the `const` agree on the suffixed form, which is what the vectors use.
- **`cnf` REQUIRED on an open mandate** (`agent_authorization.md` §Mandates using SD-JWT VCs) is enforced by the chain walk (`chain` → `intermediate_without_cnf`; a hop cannot verify without the prior `cnf.jwk`), so it is not re-tested at the constraint layer.

## What's deferred (honest)

These are not yet covered as vectors and are called out rather than silently omitted:

- **Disclosure-reorder negative** — a reordered ≥2-disclosure segment that breaks `sd_hash`. Currently covered indirectly by the binding-mismatch rejection and the byte-exact `sd_hash`-over-ordered-disclosures hash vector; a dedicated reorder vector is tracked.
- **x5c basic `keyUsage` / `pathLenConstraint`** — not asserted (the reference verifier relies on `CA:TRUE`; Node's `X509Certificate` doesn't expose basic KeyUsage). Bounded by the CA check.
- **Receipt *issuance*** — out of scope. The `receipts` category covers *verifying* a signed receipt. That a Merchant or Credential Provider MUST *return* a receipt on accept and on reject (`specification.md` §Checkout Mandate, §Payment Mandate, §Verification) is a behaviour of a running service, not something a static vector can test.
- **Dispute as one composite check** — `specification.md` §Verification > Dispute lists five steps. Each component is covered (checkout constraints via `checkout-chain`, independent `checkout_hash` via `cc_tampered_hash` (hardening), receipt `reference` binding via `receipts`, payment chain via `chain`), but no single vector runs all five against one transaction.
- **Merchant signature on `checkout_jwt`** — the spec requires a merchant-signed Checkout JWT with a non-deterministic signature scheme (`specification.md` §Checkout Mandate, §Payment Mandate). AP2's SDK does not verify that signature (`CheckoutMandateChain.extract_parsed_checkout_object` only decodes the payload), and the checkout vectors carry a placeholder signature, so it is not tested.
- **Cross-presentation budget accumulation** — the budget/recurrence vectors carry the accumulator as `context`; maintaining that state across presentations is the integrator's responsibility, not a single-vector check.

## Reproduce the vectors

See [`generators/README.md`](generators/README.md). In short: `pip install` AP2 at the pinned commit, run the generators against its SDK, and confirm each vector is accepted/rejected by AP2's own verifier (the generators assert this at mint time).
