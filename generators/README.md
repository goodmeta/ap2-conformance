# Vector generators — provenance

These scripts mint the golden vectors in `../vectors/` by driving **AP2's own
reference SDK**, so the committed vectors are the reference implementation's
actual output, not a hand-transcription. They are here for provenance: anyone can
reproduce them and confirm AP2 accepts/rejects exactly what we claim.

- `gen_ap2_vectors.py` — chain vectors (`chain.json`) + per-segment hash ground
  truth (`hash-pairs.json`). Multi-hop construction is a byte-for-byte port of
  AP2's own `chain_tests.py` flow.
- `gen_ap2_constraint_vectors.py` — payment + checkout constraint vectors and the
  linkage/receipt vectors.
- `gen_ap2_v02_vectors.py` — `mandate-semantics.json` (exact `vct`, unknown
  constraint types, required closed fields) and `receipts.json` (signed
  Checkout / Payment Receipts, via AP2's `ReceiptClient` and `jwt_helper`). It
  reads the committed `../vectors/chain.json` for its payment chains and mints
  one checkout chain of its own, so it never rewrites the other generators'
  output. Run it after the other two.

## Reproduce

```bash
python3.13 -m venv /tmp/ap2venv
/tmp/ap2venv/bin/pip install \
  "git+https://github.com/google-agentic-commerce/AP2.git@e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
/tmp/ap2venv/bin/python gen_ap2_vectors.py
/tmp/ap2venv/bin/python gen_ap2_constraint_vectors.py
/tmp/ap2venv/bin/python gen_ap2_v02_vectors.py
```

The scripts write their output next to themselves (gitignored). Each negative
vector is **asserted to be rejected by AP2's own verifier at mint time**, and
each positive vector carries AP2's own output — so a successful generation *is*
the provenance check.

## On determinism

Re-running is **not** byte-identical: ECDSA signing uses a random nonce (the
`cryptography` lib doesn't implement RFC-6979 deterministic ECDSA) and SD-JWT
disclosure salts are random. Signatures live inside the issuer JWT and cascade
through `sd_hash`, so the whole chain changes every run. That's expected — the
invariant the suite depends on is *which vectors AP2 accepts vs rejects*, which
the generators assert at mint time, not the exact bytes. The committed JSON under
`../vectors/` is the pinned source of truth; regenerate only when AP2 itself
changes (and re-pin the commit).
