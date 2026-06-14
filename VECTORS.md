# Vector schema

The vectors are plain JSON, so you can drive them from any language. This is the
contract for each file under `vectors/`. The TypeScript runner (`src/runner.ts`)
is one consumer; this document is everything you need to write another.

## The canonical clock

Evaluate every time-dependent check at a **fixed instant: `1780000000`** (Unix
seconds — the SDK clock the vectors were minted at). This drives both:

- the chain's `iat`/`exp` checks, and
- (for the `x5c` path) X.509 certificate validity windows (use `1780000000 * 1000` as ms).

Using a fixed clock is what makes the suite reproducible regardless of when it runs.

## `chain.json` — dSD-JWT chain verification

Array of:

| field | type | meaning |
|---|---|---|
| `name` | string | vector id |
| `description` | string | human note |
| `chain` | string | the compact dSD-JWT (`~~`-joined segments) |
| `kind` | `"x5c"` \| absent | absent ⇒ trust the root by the `rootKey` below; `"x5c"` ⇒ trust via the cert chain in the root header |
| `rootKey` | JWK | root issuer **public** key (when `kind` is absent) |
| `x5cTrustedRoots` | string[] | trusted root CA certs as **base64url-DER** (when `kind` is `"x5c"`) |
| `expectedAud` | string | audience the terminal hop must be bound to |
| `expectedNonce` | string | nonce the terminal hop must be bound to |
| `expect` | `"valid"` \| `"reject"` | expected outcome |
| `hardening` | bool? | `true` ⇒ stricter-than-AP2 (AP2 accepts; a hardened verifier rejects) — see profiles |
| `expectedPayloads` | object[]? | per-hop effective payloads `[open, …, closed]` for `valid` vectors |
| `reason` | string? | documented rejection reason |

**To run:** split the chain on `~~`, verify, evaluating at the canonical clock with the given `expectedAud`/`expectedNonce`.
- `expect: "valid"` → verification succeeds and the per-hop payloads deep-equal `expectedPayloads`.
- `expect: "reject"` → verification throws/errors.
- `kind: "x5c"` → resolve the root key from the root header's `x5c` chain, anchored to `x5cTrustedRoots` (decode each from **base64url** DER). An empty `x5cTrustedRoots` means "no roots configured" — a hardened verifier must refuse rather than fail open.

## `payment-constraints.json` — closed-world payment constraints

Array of:

| field | type | meaning |
|---|---|---|
| `name` | string | vector id |
| `open` | object | open payment mandate (carries `constraints`) |
| `closed` | object | closed payment mandate (the concrete payment) |
| `openCheckoutHash` | string \| null | the verified open-checkout hash, for the `payment.reference` constraint |
| `context` | `{total_amount, total_uses}` \| null | cross-presentation accumulators (budget / recurrence) |
| `ap2Violations` | string[] | the exact violation strings AP2 produces (`[]` = satisfied) |
| `valid` | bool | `true` ⇔ `ap2Violations` is empty |

**To run:** evaluate the closed mandate against the open mandate's constraints with the given context. The result must deep-equal `ap2Violations`, **except** for two vectors — `allowed_pisps_fail` and `preset_amount_mismatch` — where AP2 embeds a Python object `repr` in the message; for those, match the violation **count** instead of the bytes. Unknown constraint types MUST produce a violation (fail-closed), never be skipped.

## `checkout-constraints.json` — closed-world checkout constraints

Array of `{ name, open, checkout, ap2Violations, valid }`. Evaluate the checkout against the open checkout mandate's constraints; the result must deep-equal `ap2Violations`. Covers `allowed_merchants` and `line_items` (a bipartite max-flow match: each cart item used once, flow equals both totals).

## `linkage.json` — checkout chains + receipt references

```jsonc
{
  "checkoutChains": [
    { "name", "open", "closed", "ap2Violations": string[], "tamperHash": bool }
  ],
  "receiptReferences": [
    { "name", "chain": string, "ap2Reference": string }
  ]
}
```

- **checkoutChains** — verify the checkout→payment linkage. When `tamperHash` is `false`, violations must deep-equal `ap2Violations`. When `tamperHash` is `true`, AP2 trusts the claimed `checkout_hash` and accepts (0 violations); this is a **hardening** case — a verifier that independently recomputes the hash finds exactly one mismatch.
- **receiptReferences** — the Mandate Receipt `reference` is the base64url `sd_hash` of the **final** SD-JWT segment (incl. disclosures, no KB-JWT). Compute it over `chain` and it must equal `ap2Reference`.

## `hash-pairs.json` — per-segment canonicalization + hash math

```jsonc
{
  "rawSplitOnDoubleTilde": string[],   // the chain segments
  "segments": [
    { "compact", "issuerJwt", "disclosures", "kbJwt", "sdAlg",
      "sdJwt", "canonical", "sdHash", "issuerJwtHash", "disclosureDigests" }
  ]
}
```

Join `rawSplitOnDoubleTilde` with `~~`, split into segments, and for each segment reproduce: the canonicalization (`issuerJwt`, `disclosures`, `kbJwt`, `sdAlg`, `sdJwt`, `canonical`) and the hashes (`sdHash`, `issuerJwtHash`, and a `disclosureDigests` map of disclosure→digest). All byte-exact. This is the lowest layer; getting it right is a prerequisite for everything above.

## Two profiles

The runner classifies each result as **core** (AP2's reference SDK agrees — a conformant verifier must pass) or **hardening** (stricter-than-AP2, informational). The hardening set is the 4 `chain` vectors flagged `hardening: true` plus the one `tamperHash` checkout chain. Failing a hardening check is not a conformance failure. See [README](README.md#two-profiles-core-vs-hardening).
