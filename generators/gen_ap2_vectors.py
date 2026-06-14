#!/usr/bin/env python3
"""Generate cross-implementation golden vectors for AP2 dSD-JWT verification.

Mints REAL AP2 mandate chains using AP2's own SDK, so the TypeScript verifier is
tested against the reference implementation's actual output — not our reading of
the spec. Pinned to AP2 commit e1ea56db72a6385bce3e5c1112b3a56ce60acb43.

STABLE IDENTITIES (partial determinism): signing keys are derived from fixed
labels (stable kids + x/y coordinates) and the KB-SD-JWT `iat` clock is frozen,
so role identities and timestamps don't churn across runs.
CAVEAT — re-running is NOT byte-identical: ECDSA signing uses a random nonce
(the `cryptography` lib does not implement RFC-6979 deterministic ECDSA) and
SD-JWT disclosure salts are random. Signatures live inside the issuer JWT and
cascade through `sd_hash`, so the whole chain changes every run regardless of the
fixed keys. The committed JSON is the source of truth; regenerate only when AP2
itself changes, and commit BOTH json files from the SAME run.

Multi-hop construction is the byte-for-byte port of AP2's own
`ap2/tests/chain_tests.py::test_three_step_bank_sa_cp_merchant_flow`:
low-level `sd_jwt.create` (root) + `kb_sd_jwt.create` per hop (each binding to the
immediately-preceding SINGLE segment), assembled as `root[:-1] ~~ mid[:-1] ~~ leaf`.

Setup (one-time):
    python3.13 -m venv /tmp/ap2venv
    /tmp/ap2venv/bin/pip install \
        "git+https://github.com/google-agentic-commerce/AP2.git@e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
Run:
    /tmp/ap2venv/bin/python test/fixtures/gen_ap2_vectors.py

Each vector: {name, description, chain, rootKey(pub JWK), expectedAud,
expectedNonce, expect: "valid"|"reject", reason?, expectedPayloads?}.
Every "reject" vector is CONFIRMED to be rejected by AP2's own verifier at mint
time (so it is a true negative per AP2, not merely per our assumption).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
from types import SimpleNamespace

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from ap2.sdk.mandate import MandateClient, _canonical_chain_segment
from ap2.sdk.sdjwt import common, kb_sd_jwt, sd_jwt
from ap2.sdk.sdjwt.chain import X5cOrKidPublicKeyProvider
from ap2.sdk.utils import b64url_decode, b64url_encode
from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate, AmountRange
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument

OUT = pathlib.Path(__file__).parent / "ap2-vectors.json"
PAIRS_OUT = pathlib.Path(__file__).parent / "ap2-hash-pairs.json"

AUD, NONCE = "merchant", "nonce-1"

# Frozen issuance clock (a fixed 2026 timestamp, comfortably in the past) so iat
# is deterministic AND always passes a verifier's "iat not in the future" check.
FROZEN_NOW = 1780000000
kb_sd_jwt.time = SimpleNamespace(time=lambda: FROZEN_NOW)

# NIST P-256 group order; deterministic scalars are reduced into [1, n-1].
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def gen_key(kid: str) -> JWK:
    """Deterministically derive a P-256 signing JWK from a fixed label."""
    scalar = int.from_bytes(hashlib.sha256(kid.encode()).digest(), "big") % (_P256_ORDER - 1) + 1
    priv = ec.derive_private_key(scalar, ec.SECP256R1())
    jwk = JWK.from_pyca(priv)
    d = json.loads(jwk.export())
    d["kid"] = kid
    return JWK.from_json(json.dumps(d))


def pub(jwk: JWK) -> dict:
    return json.loads(jwk.export_public())


def make_cnf(jwk: JWK) -> dict:
    return {"jwk": json.loads(jwk.export_public())}


def payment(**ov) -> PaymentMandate:
    d = dict(
        transaction_id="tx_1",
        payee=Merchant(name="Shop", id="s-1"),
        payment_amount=Amount(amount=1000, currency="USD"),
        payment_instrument=PaymentInstrument(id="pi-1", type="credit"),
    )
    d.update(ov)
    return PaymentMandate(**d)


def root_open(issuer: JWK, holder_pub: JWK) -> str:
    """Root SD-JWT: open payment mandate (cnf = holder) signed by issuer."""
    return sd_jwt.create(
        payload=OpenPaymentMandate(constraints=[AmountRange(currency="USD", max=5000)], cnf=make_cnf(holder_pub)),
        issuer_key=issuer,
    ).sd_jwt_issuance


def hop(prev_segment: str, holder: JWK, payload, *, aud: str, nonce: str, hash_mode: str = "sd_hash") -> str:
    """One KB-SD-JWT delegation hop bound to the previous SINGLE segment."""
    return kb_sd_jwt.create(
        prev_token=common.parse_token(prev_segment),
        holder_key=holder,
        payload=payload,
        aud=aud,
        nonce=nonce,
        hash_mode=hash_mode,
    ).sd_jwt_issuance


def join(*segments: str) -> str:
    """Assemble a dSD-JWT chain: strip the trailing '~' from every non-final
    segment, then join with '~~' (AP2 chain_tests.py construction)."""
    parts = []
    for i, s in enumerate(segments):
        last = i == len(segments) - 1
        parts.append(s if last else (s[:-1] if s.endswith("~") else s))
    return "~~".join(parts)


def sign_compact(header: dict, payload: dict, key: JWK) -> str:
    """Sign a compact JWS with the given protected header + payload (ES256)."""
    jws = JWS(json.dumps(payload, separators=(",", ":")).encode())
    jws.add_signature(key, alg=header["alg"], protected=json.dumps(header, separators=(",", ":")))
    return jws.serialize(compact=True)


def craft(segment: str, signing_key: JWK | None = None, *, header_mut=None, payload_mut=None, resign: bool = True) -> str:
    """Surgically mutate one chain segment to build a HAND-BUILT NEGATIVE vector.

    `resign=True` re-signs the issuer JWT with `signing_key` after mutating the
    header/payload, so the signature stays valid and only the targeted rule is
    violated (isolates typ / binding / cnf / exp checks). `resign=False` keeps
    the original payload + signature and only re-encodes the header (used for
    alg-swaps, which a pinned verifier must reject BEFORE signature math)."""
    tilde = segment.split("~")
    h_b64, p_b64, s_b64 = tilde[0].split(".")
    header = json.loads(b64url_decode(h_b64))
    payload = json.loads(b64url_decode(p_b64))
    if header_mut:
        header_mut(header)
    if payload_mut:
        payload_mut(payload)
    if resign:
        new_ij = sign_compact(header, payload, signing_key)
    else:
        new_ij = ".".join([b64url_encode(json.dumps(header, separators=(",", ":")).encode()), p_b64, s_b64])
    return "~".join([new_ij] + tilde[1:])


# ── x5c certificate infrastructure (hand-built; AP2 helpers only do kid) ──────
CERT_NB = datetime.datetime(2025, 1, 1)
CERT_NA = datetime.datetime(2030, 1, 1)
EXPIRED_NB = datetime.datetime(2020, 1, 1)
EXPIRED_NA = datetime.datetime(2021, 1, 1)
_SERIAL = [1000]


def ec_key(scalar: int, curve=ec.SECP256R1()):
    return ec.derive_private_key(scalar, curve)


def make_cert(subject, issuer_cn, sub_pubkey, iss_privkey, ca, *, nb=CERT_NB, na=CERT_NA, sig_hash=hashes.SHA256()):
    _SERIAL[0] += 1
    ku = x509.KeyUsage(
        digital_signature=not ca, content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
            .public_key(sub_pubkey).serial_number(_SERIAL[0])
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(ku, critical=True)
            .sign(iss_privkey, sig_hash))


def der_b64url(cert) -> str:
    return b64url_encode(cert.public_bytes(Encoding.DER))


def emit_hash_pairs(chain: str) -> dict:
    """Per-segment byte-exact ground truth from AP2's common.py — drives P1
    (parse/hash) tests."""
    segs = chain.split("~~")
    total = len(segs)
    out = []
    for i, s in enumerate(segs):
        cs = _canonical_chain_segment(s, i, total)
        t = common.parse_token(cs)
        out.append({
            "compact": cs,
            "issuerJwt": t.issuer_jwt,
            "disclosures": t.disclosures,
            "kbJwt": t.kb_jwt,
            "sdAlg": t.sd_alg,
            "sdJwt": t.sd_jwt,
            "canonical": t.canonical,
            "sdHash": common.compute_sd_hash(t),
            "issuerJwtHash": common.compute_issuer_jwt_hash(t),
            "disclosureDigests": {d: common.compute_disclosure_digest(d, t.sd_alg) for d in t.disclosures},
        })
    return {"rawSplitOnDoubleTilde": segs, "segments": out}


def main() -> None:
    h = MandateClient()
    vectors: list[dict] = []

    def add(name, description, chain, root, expect, *, aud=AUD, nonce=NONCE, reason=None, payloads=None):
        v = {
            "name": name, "description": description, "chain": chain,
            "rootKey": root, "expectedAud": aud, "expectedNonce": nonce, "expect": expect,
        }
        if reason:
            v["reason"] = reason
        if payloads is not None:
            v["expectedPayloads"] = payloads
        vectors.append(v)

    def ap2_verify(chain, root_pub, *, aud=AUD, nonce=NONCE):
        return h.verify(token=chain, key_or_provider=lambda _t: JWK.from_json(root_pub.export_public()),
                        expected_aud=aud, expected_nonce=nonce)

    def assert_ap2_rejects(name, chain, root_pub, *, aud=AUD, nonce=NONCE):
        try:
            ap2_verify(chain, root_pub, aud=aud, nonce=nonce)
        except Exception:  # noqa: BLE001 — confirming AP2 itself rejects this vector
            return
        raise SystemExit(f"[FATAL] reject-vector '{name}' was ACCEPTED by AP2 — not a true negative")

    # Deterministic role keys.
    user, agent, cp, other = gen_key("user-1"), gen_key("agent-1"), gen_key("cp-1"), gen_key("other-1")

    # ── Valid 2-hop (root SD-JWT by user + terminal KB-SD-JWT by agent) ──
    root2 = root_open(user, agent)
    leaf2 = hop(root2, agent, payment(), aud=AUD, nonce=NONCE)
    chain2 = join(root2, leaf2)
    payloads2 = ap2_verify(chain2, user)
    add("valid_payment_2hop", "Root SD-JWT (user) + terminal KB-SD-JWT (agent), in budget.",
        chain2, pub(user), "valid", payloads=payloads2)

    # ── Valid 3-hop (user root -> agent intermediate[cnf=cp] -> cp terminal) ──
    mid3 = hop(root2, agent, OpenPaymentMandate(constraints=[AmountRange(currency="USD", max=5000)], cnf=make_cnf(cp)),
               aud="cp-agent", nonce="cp-nonce")
    leaf3 = hop(mid3, cp, payment(), aud=AUD, nonce=NONCE)
    chain3 = join(root2, mid3, leaf3)
    payloads3 = ap2_verify(chain3, user)
    add("valid_payment_3hop", "user root -> agent intermediate (cnf=cp) -> cp terminal.",
        chain3, pub(user), "valid", payloads=payloads3)

    # ── Valid 3-hop using issuer_jwt_hash binding on the intermediate hop ──
    mid3i = hop(root2, agent, OpenPaymentMandate(constraints=[AmountRange(currency="USD", max=5000)], cnf=make_cnf(cp)),
                aud="cp-agent", nonce="cp-nonce", hash_mode="issuer_jwt_hash")
    leaf3i = hop(mid3i, cp, payment(), aud=AUD, nonce=NONCE)
    chain3i = join(root2, mid3i, leaf3i)
    payloads3i = ap2_verify(chain3i, user)
    add("valid_payment_3hop_issuer_jwt_hash", "3-hop where the intermediate hop binds via issuer_jwt_hash.",
        chain3i, pub(user), "valid", payloads=payloads3i)

    # ── Tampered: flipped root payload byte → root signature/parse fails ──
    seg0 = chain2.split("~~")[0]
    ij = seg0.split("~")[0]
    hh, pp, ss = ij.split(".")
    pp2 = pp[:-1] + ("A" if pp[-1] != "A" else "B")
    chain_tamper = chain2.replace(ij, ".".join([hh, pp2, ss]), 1)
    assert_ap2_rejects("tampered_root_payload", chain_tamper, user)
    add("tampered_root_payload", "One byte flipped in the root issuer-JWT payload.",
        chain_tamper, pub(user), "reject", reason="root signature invalid")

    # ── Crafted: terminal hop signed by the WRONG key (cnf names agent) ──
    wrong = join(root2, hop(root2, other, payment(), aud=AUD, nonce=NONCE))
    assert_ap2_rejects("wrong_cnf_key", wrong, user)
    add("wrong_cnf_key", "Terminal hop signed by a key not named in the prior cnf.jwk.",
        wrong, pub(user), "reject", reason="hop signature does not verify under prev cnf.jwk")

    # ── Binding mismatch: terminal bound to a DIFFERENT root (sd_hash wrong) ──
    other_root = root_open(user, agent)
    leaf_bad = hop(other_root, agent, payment(), aud=AUD, nonce=NONCE)  # binds to other_root
    chain_bind = join(root2, leaf_bad)  # but presented after root2
    assert_ap2_rejects("binding_sd_hash_mismatch", chain_bind, user)
    add("binding_sd_hash_mismatch", "Terminal hop's sd_hash binds a different root than the one presented.",
        chain_bind, pub(user), "reject", reason="sd_hash mismatch")

    # ── aud / nonce mismatch (valid chain, verifier expects different values) ──
    assert_ap2_rejects("aud_mismatch", chain2, user, aud="WRONG-aud")
    add("aud_mismatch", "Valid chain, verifier expects a different audience.",
        chain2, pub(user), "reject", aud="WRONG-aud", reason="terminal aud mismatch")
    assert_ap2_rejects("nonce_mismatch", chain2, user, nonce="WRONG-nonce")
    add("nonce_mismatch", "Valid chain, verifier expects a different nonce.",
        chain2, pub(user), "reject", nonce="WRONG-nonce", reason="terminal nonce mismatch")

    # ── Wrong root key (valid chain verified against an unrelated key) ──
    assert_ap2_rejects("wrong_root_key", chain2, other)
    add("wrong_root_key", "Valid chain verified against an unrelated root key.",
        chain2, pub(other), "reject", reason="root signature does not verify under given key")

    # ── Hand-built negative vectors (PLAN §7). Each is CONFIRMED rejected by
    #    AP2's own verifier at mint time, so it is a true negative per AP2. ──
    root2_pt = common.parse_token(root2)
    ijh = common.compute_issuer_jwt_hash(root2_pt)

    # wrong typ on the terminal hop (re-signed so the signature stays valid)
    v = join(root2, craft(leaf2, agent, header_mut=lambda hdr: hdr.__setitem__("typ", "application/bogus+jwt")))
    assert_ap2_rejects("wrong_typ", v, user)
    add("wrong_typ", "Terminal hop carries an unrecognized 'typ'.", v, pub(user), "reject", reason="unexpected typ")

    # BOTH binding claims present
    v = join(root2, craft(leaf2, agent, payload_mut=lambda p: p.__setitem__("issuer_jwt_hash", ijh)))
    assert_ap2_rejects("both_binding_claims", v, user)
    add("both_binding_claims", "Terminal hop has BOTH sd_hash and issuer_jwt_hash.",
        v, pub(user), "reject", reason="exactly one binding claim required")

    # NEITHER binding claim
    v = join(root2, craft(leaf2, agent, payload_mut=lambda p: p.pop("sd_hash", None)))
    assert_ap2_rejects("neither_binding_claim", v, user)
    add("neither_binding_claim", "Terminal hop has NEITHER sd_hash nor issuer_jwt_hash.",
        v, pub(user), "reject", reason="exactly one binding claim required")

    # Terminal-typ hop carrying a cnf (mint a cnf-bearing hop @ merchant aud, flip typ->terminal)
    inter_m = hop(root2, agent, OpenPaymentMandate(constraints=[], cnf=make_cnf(cp)), aud=AUD, nonce=NONCE)
    v = join(root2, craft(inter_m, agent, header_mut=lambda hdr: hdr.__setitem__("typ", "kb+sd-jwt")))
    assert_ap2_rejects("terminal_with_cnf", v, user)
    add("terminal_with_cnf", "A terminal-typ hop that illegally carries a cnf claim.",
        v, pub(user), "reject", reason="terminal MUST NOT carry cnf")

    # Intermediate-typ hop with no cnf (mint terminal, flip typ->intermediate)
    v = join(root2, craft(leaf2, agent, header_mut=lambda hdr: hdr.__setitem__("typ", "kb+sd-jwt+kb")))
    assert_ap2_rejects("intermediate_without_cnf", v, user)
    add("intermediate_without_cnf", "An intermediate-typ hop that is missing its required cnf claim.",
        v, pub(user), "reject", reason="intermediate requires cnf")

    # Expired (exp well in the past)
    v = join(root2, craft(leaf2, agent, payload_mut=lambda p: p.__setitem__("exp", FROZEN_NOW - 100000)))
    assert_ap2_rejects("expired", v, user)
    add("expired", "Terminal hop carries an exp in the past.", v, pub(user), "reject", reason="token expired")

    # Alg downgrade: 'none' on the root header
    v = join(craft(root2, header_mut=lambda hdr: hdr.__setitem__("alg", "none"), resign=False), leaf2)
    assert_ap2_rejects("alg_swap_none_root", v, user)
    add("alg_swap_none_root", "Root header alg downgraded to 'none'.", v, pub(user), "reject", reason="alg not ES256")

    # Alg swap: HS256 on the terminal hop header
    v = join(root2, craft(leaf2, header_mut=lambda hdr: hdr.__setitem__("alg", "HS256"), resign=False))
    assert_ap2_rejects("alg_swap_hs256_hop", v, user)
    add("alg_swap_hs256_hop", "Terminal hop header alg swapped to HS256.", v, pub(user), "reject", reason="alg not ES256")

    # ── x5c trust-anchoring vectors (P4). Cert chains are hand-built (AP2 helpers
    #    only do kid). The root SD-JWT is signed by the leaf key and carries an
    #    x5c header [leaf, intermediate]; the trusted root is NOT in the chain. ──
    def add_x5c(name, description, chain, trusted_root_ders, expect, *, reason=None, payloads=None, hardening=False):
        v = {"name": name, "description": description, "chain": chain, "kind": "x5c",
             "x5cTrustedRoots": trusted_root_ders, "expectedAud": AUD, "expectedNonce": NONCE, "expect": expect}
        if reason:
            v["reason"] = reason
        if hardening:
            v["hardening"] = True  # AP2 ACCEPTS this; we reject (stricter, H2)
        if payloads is not None:
            v["expectedPayloads"] = payloads
        vectors.append(v)

    def ap2_x5c(chain, trusted_roots):
        provider = X5cOrKidPublicKeyProvider(lambda _k: None, trusted_roots=trusted_roots)
        return h.verify(token=chain, key_or_provider=provider, expected_aud=AUD, expected_nonce=NONCE)

    def assert_ap2_x5c_accepts(name, chain, trusted_roots):
        try:
            ap2_x5c(chain, trusted_roots)
        except Exception as e:  # noqa: BLE001
            raise SystemExit(f"[FATAL] x5c hardening vector '{name}' was REJECTED by AP2 ({e}) — not a stricter-than-AP2 case")

    def assert_ap2_x5c_rejects(name, chain, trusted_roots):
        try:
            ap2_x5c(chain, trusted_roots)
        except Exception:  # noqa: BLE001
            return
        raise SystemExit(f"[FATAL] x5c reject vector '{name}' was ACCEPTED by AP2")

    def x5c_chain(sign_jwk, x5c_certs, alg=None):
        # Build the SD-JWT structure with the P-256 leaf (the lib hardcodes
        # ES256), then re-sign with `sign_jwk` and add the x5c header (+ alg
        # override for the P-384 wrong-curve case).
        base = sd_jwt.create(
            payload=OpenPaymentMandate(constraints=[AmountRange(currency="USD", max=5000)], cnf=make_cnf(agent)),
            issuer_key=leaf_jwk,
        ).sd_jwt_issuance

        def mut(hdr):
            hdr["x5c"] = [der_b64url(c) for c in x5c_certs]
            if alg:
                hdr["alg"] = alg

        rx = craft(base, sign_jwk, header_mut=mut)
        return join(rx, hop(rx, agent, payment(), aud=AUD, nonce=NONCE))

    root_ca_k, inter_k, leaf_k = ec_key(0xA1), ec_key(0xB2), ec_key(0xC3)
    leaf_jwk = JWK.from_pyca(leaf_k)
    root_ca = make_cert("ap2-root", "ap2-root", root_ca_k.public_key(), root_ca_k, True)
    inter = make_cert("ap2-intermediate", "ap2-root", inter_k.public_key(), root_ca_k, True)
    leaf = make_cert("ap2-leaf", "ap2-intermediate", leaf_k.public_key(), inter_k, False)
    root_ca_der = der_b64url(root_ca)

    # valid: leaf -> intermediate -> (trusted) root
    cx = x5c_chain(leaf_jwk, [leaf, inter])
    payloads_x5c = ap2_x5c(cx, [root_ca])
    add_x5c("valid_x5c", "Root signed by an x5c leaf chaining leaf->intermediate->trusted root.",
            cx, [root_ca_der], "valid", payloads=payloads_x5c)

    # untrusted root (we provide an unrelated trusted root) — AP2 rejects too
    unrel_k = ec_key(0xD4)
    unrel_root = make_cert("unrelated-root", "unrelated-root", unrel_k.public_key(), unrel_k, True)
    assert_ap2_x5c_rejects("x5c_untrusted_root", cx, [unrel_root])
    add_x5c("x5c_untrusted_root", "Valid chain, but anchored against an unrelated trusted root.",
            cx, [der_b64url(unrel_root)], "reject", reason="does not chain to a trusted root")

    # fail-open (H2): valid chain, but NO trusted roots configured — AP2 accepts, we reject
    assert_ap2_x5c_accepts("x5c_fail_open", cx, None)
    add_x5c("x5c_fail_open", "Valid chain with NO trusted roots configured (AP2 fails open).",
            cx, [], "reject", reason="no trustedRoots — refusing to fail open", hardening=True)

    # expired leaf (H2): AP2 ignores validity, we reject
    leaf_exp = make_cert("ap2-leaf-expired", "ap2-intermediate", leaf_k.public_key(), inter_k, False,
                         nb=EXPIRED_NB, na=EXPIRED_NA)
    cx_exp = x5c_chain(leaf_jwk, [leaf_exp, inter])
    assert_ap2_x5c_accepts("x5c_expired", cx_exp, [root_ca])
    add_x5c("x5c_expired", "Leaf certificate is expired (AP2 does not check validity).",
            cx_exp, [root_ca_der], "reject", reason="cert outside validity window", hardening=True)

    # non-CA intermediate (H2): same subject CN + key as the real intermediate
    # (so name-chaining + signature pass) but basicConstraints CA:FALSE. AP2
    # ignores basicConstraints and accepts; we reject on the CA check.
    inter_nonca = make_cert("ap2-intermediate", "ap2-root", inter_k.public_key(), root_ca_k, False)
    cx_nonca = x5c_chain(leaf_jwk, [leaf, inter_nonca])
    assert_ap2_x5c_accepts("x5c_non_ca_intermediate", cx_nonca, [root_ca])
    add_x5c("x5c_non_ca_intermediate", "Intermediate lacks basicConstraints CA:TRUE (AP2 ignores it).",
            cx_nonca, [root_ca_der], "reject", reason="intermediate is not a CA", hardening=True)

    # wrong-curve leaf (H2/H1): leaf key is P-384 (root sig ES384) — AP2 accepts, we reject
    leaf384_k = ec_key(0xE5, ec.SECP384R1())
    leaf384 = make_cert("ap2-leaf-p384", "ap2-intermediate", leaf384_k.public_key(), inter_k, False)
    cx384 = x5c_chain(JWK.from_pyca(leaf384_k), [leaf384, inter], alg="ES384")
    assert_ap2_x5c_accepts("x5c_wrong_curve_leaf", cx384, [root_ca])
    add_x5c("x5c_wrong_curve_leaf", "Leaf key is P-384, not P-256 (AP2 accepts ES384).",
            cx384, [root_ca_der], "reject", reason="leaf not EC P-256", hardening=True)

    PAIRS_OUT.write_text(json.dumps(emit_hash_pairs(chain2), indent=2) + "\n")
    OUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors -> {OUT}")
    print(f"wrote hash pairs -> {PAIRS_OUT}")
    for v in vectors:
        print(f"  - {v['name']}: expect={v['expect']}" + (f" ({len(v['expectedPayloads'])} payloads)" if v.get("expectedPayloads") else ""))


if __name__ == "__main__":
    main()
