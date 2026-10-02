#!/usr/bin/env python3
"""Golden vectors for the AP2 v0.2 rules the other generators do not reach.

Two files, both minted by AP2's own SDK at commit e1ea56d (v0.2 shipped in
b4587ac, PR #233; e1ea56d is four commits later):

  ap2-mandate-semantics.json  — mandate-type rules: exact `vct` (incl. version
                                suffix), unknown constraint types, required
                                closed-mandate fields, `cnf` on open mandates.
  ap2-receipts.json           — signed Checkout / Payment Receipts: ES256
                                signature under the issuer key, required fields
                                per schema, and `reference` = sd_hash of the
                                final segment of the closed mandate chain.

Every vector records the spec rule it encodes (`rule`, `cite`). Each one is
confirmed against AP2's SDK at mint time:

  - core `reject`   → the SDK raises or reports >= 1 violation
  - core `accept`   → the SDK reports zero violations
  - hardening       → the SDK ACCEPTS (asserted), but the cited spec text
                      requires a rejection; a hardened verifier rejects

This generator never rewrites the files the other two generators own, so the
existing (non-byte-reproducible) chain vectors are not churned.

Run (same venv as the other generators):
    /tmp/ap2venv/bin/python generators/gen_ap2_v02_vectors.py
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from jwcrypto.jwk import JWK  # noqa: E402

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain  # noqa: E402
from ap2.sdk.jwt_helper import create_jwt  # noqa: E402
from ap2.sdk.mandate import MandateClient, _canonical_chain_segment  # noqa: E402
from ap2.sdk.payment_mandate_chain import PaymentMandateChain  # noqa: E402
from ap2.sdk.receipt_wrapper import ReceiptClient  # noqa: E402
from ap2.sdk.sdjwt import common, sd_jwt  # noqa: E402
from ap2.sdk.utils import b64url_decode, b64url_encode, compute_sha256_b64url  # noqa: E402
from ap2.sdk.generated.checkout_mandate import CheckoutMandate  # noqa: E402
from ap2.sdk.generated.checkout_receipt import CheckoutReceipt  # noqa: E402
from ap2.sdk.generated.open_checkout_mandate import (  # noqa: E402
    AllowedMerchants, Item as ReqItem, LineItemRequirements, LineItems, OpenCheckoutMandate)
from ap2.sdk.generated.open_payment_mandate import AmountRange, OpenPaymentMandate  # noqa: E402
from ap2.sdk.generated.payment_mandate import PaymentMandate  # noqa: E402
from ap2.sdk.generated.payment_receipt import PaymentReceipt  # noqa: E402
from ap2.sdk.generated.types.amount import Amount  # noqa: E402
from ap2.sdk.generated.types.checkout import Checkout, Status  # noqa: E402
from ap2.sdk.generated.types.item import Item  # noqa: E402
from ap2.sdk.generated.types.line_item import LineItem  # noqa: E402
from ap2.sdk.generated.types.link import Link  # noqa: E402
from ap2.sdk.generated.types.merchant import Merchant  # noqa: E402
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument  # noqa: E402
from ap2.sdk.generated.types.total import Total  # noqa: E402

from gen_ap2_vectors import AUD, NONCE, gen_key, hop, join, make_cnf, pub  # noqa: E402

HERE = pathlib.Path(__file__).parent
SEM_OUT = HERE / "ap2-mandate-semantics.json"
RCPT_OUT = HERE / "ap2-receipts.json"
COMMITTED_CHAINS = HERE.parent / "vectors" / "chain.json"

CNF = {"jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}}
SHOP = Merchant(id="s-1", name="Shop", website="shop.example")

# Spec citations, all at google-agentic-commerce/AP2 @ e1ea56db72a6385bce3e5c1112b3a56ce60acb43.
CITE_VERSIONING = "docs/ap2/specification.md §Mandate Versioning"
CITE_PAY_TYPE = "docs/ap2/payment_mandate.md §Type"
CITE_CO_TYPE = "docs/ap2/checkout_mandate.md §Type"
CITE_UNKNOWN = "docs/ap2/agent_authorization.md §Verification and Processing Rules (step 3)"
CITE_CLAIMS = "docs/ap2/agent_authorization.md §Mandates using SD-JWT VCs"
CITE_RECEIPT = "docs/ap2/agent_authorization.md §Action Authorization (Mandate Receipt)"
CITE_DISPUTE = "docs/ap2/specification.md §Verification > Dispute"


def dump(model) -> dict:
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def drop(d: dict, key: str) -> dict:
    return {k: v for k, v in d.items() if k != key}


# ── mandate-semantics ─────────────────────────────────────────────────────────

def sdk_outcome(mandate: str, open_d: dict, closed_d: dict) -> tuple[str, str]:
    """Run AP2's own chain parse + verify. Returns ("accept"|"reject", detail)."""
    try:
        if mandate == "payment":
            violations = PaymentMandateChain.parse([open_d, closed_d]).verify()
        else:
            violations = CheckoutMandateChain.parse([open_d, closed_d]).verify(
                checkout_jwt=closed_d.get("checkout_jwt"))
    except Exception as e:  # noqa: BLE001 — recording AP2's own rejection
        return "reject", f"{type(e).__name__}: {str(e).splitlines()[0]}"
    return ("reject", f"violations: {violations}") if violations else ("accept", "no violations")


def checkout_jwt_of(co: Checkout) -> str:
    hdr = b64url_encode(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
    pl = b64url_encode(json.dumps(dump(co)).encode())
    return f"{hdr}.{pl}.sig"


def mint_semantics() -> list[dict]:
    vectors: list[dict] = []

    def add(name, mandate, open_d, closed_d, expect, rule, cite, *, hardening=False):
        sdk, detail = sdk_outcome(mandate, open_d, closed_d)
        if hardening:
            # Stricter than AP2: the SDK must ACCEPT, the spec text requires a reject.
            if sdk != "accept":
                raise SystemExit(f"[FATAL] hardening vector '{name}': AP2 SDK did not accept ({detail})")
        elif sdk != expect:
            raise SystemExit(f"[FATAL] '{name}': expected AP2 SDK to {expect}, it did {sdk} ({detail})")
        v = {"name": name, "mandate": mandate, "open": open_d, "closed": closed_d,
             "expect": expect, "ap2Outcome": sdk, "rule": rule, "cite": cite}
        if hardening:
            v["hardening"] = True
        vectors.append(v)

    # Payment: the same open/closed pair the constraint vectors use (amount_range_pass).
    p_open = dump(OpenPaymentMandate(constraints=[AmountRange(currency="USD", min=100, max=5000)], cnf=CNF))
    p_closed = dump(PaymentMandate(
        transaction_id="tx_1", payee=Merchant(id="s-1", name="Shop"),
        payment_amount=Amount(amount=1000, currency="USD"),
        payment_instrument=PaymentInstrument(id="pi-1", type="credit")))

    add("payment_vct_control", "payment", p_open, p_closed, "accept",
        "Correct vct on both mandates; control for the vct negatives below.",
        f"{CITE_PAY_TYPE}; {CITE_VERSIONING}")
    for name, vct in [("payment_closed_vct_wrong_version", "mandate.payment.2"),
                      ("payment_closed_vct_no_version", "mandate.payment"),
                      ("payment_closed_vct_is_open_type", "mandate.payment.open.1")]:
        add(name, "payment", p_open, dict(p_closed, vct=vct), "reject",
            f"Closed Payment Mandate vct MUST be exactly 'mandate.payment.1' (got '{vct}').",
            f"{CITE_PAY_TYPE}; {CITE_VERSIONING}")
    for name, vct in [("payment_open_vct_wrong_version", "mandate.payment.open.2"),
                      ("payment_open_vct_no_version", "mandate.payment.open"),
                      ("payment_open_vct_is_closed_type", "mandate.payment.1")]:
        add(name, "payment", dict(p_open, vct=vct), p_closed, "reject",
            f"Open Payment Mandate vct MUST be exactly 'mandate.payment.open.1' (got '{vct}').",
            f"{CITE_PAY_TYPE}; {CITE_VERSIONING}")

    add("payment_unknown_constraint", "payment",
        dict(p_open, constraints=p_open["constraints"] + [{"type": "payment.unknown_x"}]), p_closed, "reject",
        "Unknown constraint type MUST be treated as failing evaluation (even next to a satisfied one).",
        CITE_UNKNOWN)
    add("payment_unknown_constraint_rdns", "payment",
        dict(p_open, constraints=p_open["constraints"] + [{"type": "com.example.loyalty_tier", "min": "gold"}]),
        p_closed, "reject",
        "An rDNS-named extension constraint the verifier does not know MUST fail evaluation.",
        CITE_UNKNOWN)

    for field in ["transaction_id", "payee", "payment_amount", "payment_instrument"]:
        add(f"payment_closed_missing_{field}", "payment", p_open, drop(p_closed, field), "reject",
            f"Closed Payment Mandate MUST include required field '{field}'.",
            f"{CITE_CLAIMS}; code/sdk/schemas/ap2/payment_mandate.json#/required")
    # `cnf` REQUIRED on an open mandate (CITE_CLAIMS) is deliberately NOT a vector
    # here: it is enforced by the chain walk (the next hop cannot verify without
    # the previous `cnf.jwk`; see chain.json `intermediate_without_cnf`), so a
    # verifier that checks it there and not again at constraint evaluation is
    # still conformant. Testing it at this layer would fail it for layering.
    add("payment_closed_missing_vct", "payment", p_open, drop(p_closed, "vct"), "reject",
        "vct is REQUIRED. AP2's SDK fills it from a model default and accepts.",
        f"{CITE_CLAIMS}; code/sdk/schemas/ap2/payment_mandate.json#/required", hardening=True)

    # Checkout: the cc_valid shape from linkage.json.
    co = Checkout(id="co_1", merchant=SHOP, status=Status.completed, currency="USD",
                  line_items=[LineItem(id="li_A", item=Item(id="A", title="A", price=0), quantity=1,
                                       totals=[Total(type="total", amount=0)])],
                  totals=[Total(type="total", amount=0)],
                  links=[Link(type="self", url="https://shop.example/checkout")])
    cjwt = checkout_jwt_of(co)
    c_closed = dump(CheckoutMandate(checkout_jwt=cjwt, checkout_hash=compute_sha256_b64url(cjwt)))
    c_open = dump(OpenCheckoutMandate(constraints=[
        AllowedMerchants(allowed=[SHOP]),
        LineItems(items=[LineItemRequirements(id="r1", acceptable_items=[ReqItem(id="A", title="A")], quantity=1)]),
    ], cnf=CNF))

    add("checkout_vct_control", "checkout", c_open, c_closed, "accept",
        "Correct vct on both mandates; control for the vct negatives below.",
        f"{CITE_CO_TYPE}; {CITE_VERSIONING}")
    add("checkout_closed_vct_wrong_version", "checkout", c_open, dict(c_closed, vct="mandate.checkout.2"), "reject",
        "Closed Checkout Mandate vct MUST be exactly 'mandate.checkout.1'.", f"{CITE_CO_TYPE}; {CITE_VERSIONING}")
    add("checkout_closed_vct_is_open_type", "checkout", c_open, dict(c_closed, vct="mandate.checkout.open.1"),
        "reject", "Closed Checkout Mandate vct MUST be exactly 'mandate.checkout.1'.",
        f"{CITE_CO_TYPE}; {CITE_VERSIONING}")
    add("checkout_open_vct_wrong_version", "checkout", dict(c_open, vct="mandate.checkout.open.2"), c_closed,
        "reject", "Open Checkout Mandate vct MUST be exactly 'mandate.checkout.open.1'.",
        f"{CITE_CO_TYPE}; {CITE_VERSIONING}")
    add("checkout_unknown_constraint", "checkout",
        dict(c_open, constraints=c_open["constraints"] + [{"type": "checkout.unknown_x"}]), c_closed, "reject",
        "Unknown constraint type MUST be treated as failing evaluation.", CITE_UNKNOWN)
    for field in ["checkout_jwt", "checkout_hash"]:
        add(f"checkout_closed_missing_{field}", "checkout", c_open, drop(c_closed, field), "reject",
            f"Closed Checkout Mandate MUST include required field '{field}'.",
            f"{CITE_CLAIMS}; code/sdk/schemas/ap2/checkout_mandate.json#/required")
    add("checkout_closed_missing_vct", "checkout", c_open, drop(c_closed, "vct"), "reject",
        "vct is REQUIRED. AP2's SDK fills it from a model default and accepts.",
        f"{CITE_CLAIMS}; code/sdk/schemas/ap2/checkout_mandate.json#/required", hardening=True)
    return vectors


# ── receipts ──────────────────────────────────────────────────────────────────

def receipt_reference(chain: str) -> str:
    """sd_hash of the final segment, exactly as the linkage generator computes it."""
    segs = chain.split("~~")
    last = common.parse_token(_canonical_chain_segment(segs[-1], len(segs) - 1, len(segs)))
    return common.compute_sd_hash(last)


def mint_checkout_chain() -> str:
    """A real 2-hop Checkout Mandate chain: user-signed open checkout mandate
    (cnf = agent) + agent KB-SD-JWT closing it. Verified by AP2 at mint time."""
    user, agent = gen_key("user-1"), gen_key("agent-1")
    co = Checkout(id="co_1", merchant=SHOP, status=Status.completed, currency="USD",
                  line_items=[LineItem(id="li_A", item=Item(id="A", title="A", price=0), quantity=1,
                                       totals=[Total(type="total", amount=0)])],
                  totals=[Total(type="total", amount=0)],
                  links=[Link(type="self", url="https://shop.example/checkout")])
    cjwt = checkout_jwt_of(co)
    root = sd_jwt.create(
        payload=OpenCheckoutMandate(constraints=[
            AllowedMerchants(allowed=[SHOP]),
            LineItems(items=[LineItemRequirements(id="r1", acceptable_items=[ReqItem(id="A", title="A")],
                                                  quantity=1)]),
        ], cnf=make_cnf(agent)),
        issuer_key=user,
    ).sd_jwt_issuance
    leaf = hop(root, agent, CheckoutMandate(checkout_jwt=cjwt, checkout_hash=compute_sha256_b64url(cjwt)),
               aud=AUD, nonce=NONCE)
    chain = join(root, leaf)
    payloads = MandateClient().verify(
        token=chain, key_or_provider=lambda _t: JWK.from_json(user.export_public()),
        expected_aud=AUD, expected_nonce=NONCE)
    violations = CheckoutMandateChain.parse(payloads).verify(checkout_jwt=cjwt)
    if violations:
        raise SystemExit(f"[FATAL] minted checkout chain fails AP2 constraints: {violations}")
    return chain


def sdk_verify_receipt(token: str, issuer: JWK, chain: str, kind: str) -> dict:
    """AP2's ReceiptClient.verify_receipt. The SDK leaves the reference lookup to
    a caller callback; per specification.md §Dispute the reference must equal the
    sd_hash of the closed mandate, so that is the callback."""
    ref = receipt_reference(chain)
    return ReceiptClient().verify_receipt(
        receipt_jwt=token, receipt_issuer_public_key=JWK.from_json(issuer.export_public()),
        has_reference_in_store_cb=lambda r: r == ref, is_payment_receipt=(kind == "payment"))


def mint_receipts() -> list[dict]:
    issuer, other = gen_key("receipt-issuer-1"), gen_key("other-1")
    pay_chain = next(v["chain"] for v in json.loads(COMMITTED_CHAINS.read_text()) if v["name"] == "valid_payment_2hop")
    pay_chain_3 = next(v["chain"] for v in json.loads(COMMITTED_CHAINS.read_text()) if v["name"] == "valid_payment_3hop")
    co_chain = mint_checkout_chain()
    client = ReceiptClient()
    closed_pm = PaymentMandate(transaction_id="tx_1", payee=Merchant(name="Shop", id="s-1"),
                               payment_amount=Amount(amount=1000, currency="USD"),
                               payment_instrument=PaymentInstrument(id="pi-1", type="credit"))

    def pay_receipt(reference: str) -> dict:
        r = client.create_payment_receipt(closed_pm, reference)
        return r.model_dump(mode="json", exclude_none=True)

    def co_receipt(reference: str) -> dict:
        r = client.create_checkout_receipt("shop.example", reference, "order_1")
        return r.model_dump(mode="json", exclude_none=True)

    def sign(payload: dict, key: JWK) -> str:
        return create_jwt({"alg": "ES256"}, payload, key)

    vectors: list[dict] = []

    def add(name, kind, token, chain, expect, rule, cite):
        res = sdk_verify_receipt(token, issuer, chain, kind)
        sdk = "accept" if res.get("verified") is True else "reject"
        if sdk != expect:
            raise SystemExit(f"[FATAL] receipt '{name}': expected AP2 SDK to {expect}, got {res}")
        vectors.append({"name": name, "kind": kind, "receiptJwt": token, "issuerPublicKey": pub(issuer),
                        "mandateChain": chain, "expect": expect,
                        "ap2Result": "verified" if sdk == "accept" else res["error"], "rule": rule, "cite": cite})

    pay_ok = sign(pay_receipt(receipt_reference(pay_chain)), issuer)
    add("payment_receipt_valid", "payment", pay_ok, pay_chain, "accept",
        "ES256 receipt signed by the issuer; reference = sd_hash of the final segment of the closed mandate chain.",
        f"{CITE_RECEIPT}; {CITE_DISPUTE}; code/sdk/schemas/ap2/payment_receipt.json")
    add("payment_receipt_valid_3hop", "payment", sign(pay_receipt(receipt_reference(pay_chain_3)), issuer),
        pay_chain_3, "accept",
        "Reference is over the FINAL SD-JWT of a 3-hop chain, not the root.", f"{CITE_RECEIPT}; {CITE_DISPUTE}")
    add("payment_receipt_wrong_key", "payment", sign(pay_receipt(receipt_reference(pay_chain)), other), pay_chain,
        "reject", "Receipt not signed by the expected issuer key MUST NOT verify.", CITE_RECEIPT)
    h, p, s = pay_ok.split(".")
    tampered = json.loads(b64url_decode(p))
    tampered["iss"] = "attacker.example"
    tampered_tok = ".".join([h, b64url_encode(json.dumps(tampered).encode()), s])
    add("payment_receipt_tampered_payload", "payment", tampered_tok, pay_chain, "reject",
        "Payload altered after signing; signature MUST NOT verify.", CITE_RECEIPT)
    add("payment_receipt_reference_mismatch", "payment", sign(pay_receipt(receipt_reference(pay_chain_3)), issuer),
        pay_chain, "reject",
        "Payment Receipt reference MUST match the hash of the closed Payment Mandate presented.",
        CITE_DISPUTE)
    add("payment_receipt_reference_is_root_hash", "payment",
        sign(pay_receipt(common.compute_sd_hash(common.parse_token(
            _canonical_chain_segment(pay_chain.split("~~")[0], 0, len(pay_chain.split("~~")))))), issuer),
        pay_chain, "reject",
        "Reference computed over the ROOT (open) segment instead of the final closed segment MUST NOT match.",
        f"{CITE_RECEIPT}; {CITE_DISPUTE}")
    add("payment_receipt_missing_payment_id", "payment",
        sign(drop(pay_receipt(receipt_reference(pay_chain)), "payment_id"), issuer), pay_chain, "reject",
        "Payment Receipt MUST carry required field 'payment_id'.",
        "code/sdk/schemas/ap2/payment_receipt.json#/required")
    add("payment_receipt_missing_reference", "payment",
        sign(drop(pay_receipt(receipt_reference(pay_chain)), "reference"), issuer), pay_chain, "reject",
        "Receipt MUST carry 'reference'.", f"{CITE_RECEIPT}; code/sdk/schemas/ap2/payment_receipt.json#/required")
    err = dict(pay_receipt(receipt_reference(pay_chain)), status="Error")
    add("payment_receipt_error_without_error_code", "payment", sign(err, issuer), pay_chain, "reject",
        "An error receipt MUST carry an 'error' code.",
        f"{CITE_RECEIPT}; code/sdk/schemas/ap2/payment_receipt.json (Error variant)")

    add("checkout_receipt_valid", "checkout", sign(co_receipt(receipt_reference(co_chain)), issuer), co_chain,
        "accept", "Checkout Receipt reference = sd_hash of the final segment of the closed Checkout Mandate chain.",
        f"{CITE_RECEIPT}; {CITE_DISPUTE}; code/sdk/schemas/ap2/checkout_receipt.json")
    add("checkout_receipt_reference_mismatch", "checkout", sign(co_receipt(receipt_reference(pay_chain)), issuer),
        co_chain, "reject",
        "Checkout Receipt reference MUST match the hash of the closed Checkout Mandate presented.", CITE_DISPUTE)
    add("checkout_receipt_wrong_key", "checkout", sign(co_receipt(receipt_reference(co_chain)), other), co_chain,
        "reject", "Receipt not signed by the expected issuer key MUST NOT verify.", CITE_RECEIPT)
    return vectors


def main() -> None:
    sem = mint_semantics()
    rc = mint_receipts()
    SEM_OUT.write_text(json.dumps(sem, indent=2) + "\n")
    RCPT_OUT.write_text(json.dumps(rc, indent=2) + "\n")
    print(f"wrote {len(sem)} mandate-semantics -> {SEM_OUT.name}, {len(rc)} receipts -> {RCPT_OUT.name}")
    for v in sem + rc:
        print(f"  - {v['name']}: expect={v['expect']}" + (" [hardening]" if v.get("hardening") else ""))


if __name__ == "__main__":
    main()
