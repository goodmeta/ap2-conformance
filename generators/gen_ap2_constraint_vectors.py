#!/usr/bin/env python3
"""Golden vectors for AP2 payment-constraint evaluation (P5).

Calls AP2's own `check_payment_constraints` (commit e1ea56d) on hand-built
open/closed mandate pairs and records the exact violation list. Pure data (no
crypto) → fully deterministic; re-running does not churn.

Run: /tmp/ap2venv/bin/python test/fixtures/gen_ap2_constraint_vectors.py
"""
from __future__ import annotations

import json
import pathlib

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.constraints import MandateContext, check_checkout_constraints, check_payment_constraints
from ap2.sdk.mandate import _canonical_chain_segment
from ap2.sdk.sdjwt import common
from ap2.sdk.utils import b64url_encode, compute_sha256_b64url
from ap2.sdk.generated.open_payment_mandate import (
    AgentRecurrence, AllowedPayees, AllowedPaymentInstruments, AllowedPisps,
    AmountRange, Budget, ExecutionDate, Frequency, OpenPaymentMandate, PaymentReference)
from ap2.sdk.generated.open_checkout_mandate import (
    AllowedMerchants, Item as ReqItem, LineItemRequirements, LineItems, OpenCheckoutMandate)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.link import Link
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.pisp import PISP
from ap2.sdk.generated.types.total import Total

HERE = pathlib.Path(__file__).parent
OUT = HERE / "ap2-constraint-vectors.json"
CO_OUT = HERE / "ap2-checkout-constraint-vectors.json"
LINK_OUT = HERE / "ap2-linkage-vectors.json"
CNF = {"jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}}
PISP_A = PISP(legal_name="Acme PISP Ltd", brand_name="Acme", domain_name="acme-pisp.example")

vectors: list[dict] = []
co_vectors: list[dict] = []


def open_pm(constraints, **preset):
    return OpenPaymentMandate(constraints=constraints, cnf=CNF, **preset)


def closed_pm(**ov):
    d = dict(transaction_id="tx_1", payee=Merchant(id="s-1", name="Shop"),
             payment_amount=Amount(amount=1000, currency="USD"),
             payment_instrument=PaymentInstrument(id="pi-1", type="credit"))
    d.update(ov)
    return PaymentMandate(**d)


def add(name, om, cm, *, hash=None, ctx=None):
    violations = check_payment_constraints(om, cm, open_checkout_hash=hash, mandate_context=ctx)
    vectors.append({
        "name": name,
        "open": om.model_dump(mode="json", by_alias=True, exclude_none=True),
        "closed": cm.model_dump(mode="json", by_alias=True, exclude_none=True),
        "openCheckoutHash": hash,
        "context": {"total_amount": ctx.total_amount, "total_uses": ctx.total_uses} if ctx else None,
        "ap2Violations": violations,
        "valid": len(violations) == 0,
    })


def main() -> None:
    AR = lambda **k: AmountRange(currency="USD", **k)

    # amount_range
    add("amount_range_pass", open_pm([AR(max=5000, min=100)]), closed_pm())
    add("amount_range_over", open_pm([AR(max=500)]), closed_pm(payment_amount=Amount(amount=1000, currency="USD")))
    add("amount_range_under", open_pm([AR(max=5000, min=2000)]), closed_pm())
    add("amount_range_currency", open_pm([AR(max=5000)]), closed_pm(payment_amount=Amount(amount=1000, currency="EUR")))

    # allowed_payees
    add("allowed_payees_pass", open_pm([AllowedPayees(allowed=[Merchant(id="s-1", name="Shop")])]), closed_pm())
    add("allowed_payees_fail", open_pm([AllowedPayees(allowed=[Merchant(id="other", name="Other")])]), closed_pm())

    # allowed_payment_instruments
    add("allowed_instruments_pass", open_pm([AllowedPaymentInstruments(allowed=[PaymentInstrument(id="pi-1", type="credit")])]), closed_pm())
    add("allowed_instruments_fail", open_pm([AllowedPaymentInstruments(allowed=[PaymentInstrument(id="pi-X", type="credit")])]), closed_pm())

    # allowed_pisps
    add("allowed_pisps_pass", open_pm([AllowedPisps(allowed=[PISP_A])]), closed_pm(pisp=PISP_A))
    add("allowed_pisps_fail", open_pm([AllowedPisps(allowed=[PISP_A])]),
        closed_pm(pisp=PISP(legal_name="Other", brand_name="Other", domain_name="other.example")))

    # budget (max is MAJOR-unit float → *100 cents)
    add("budget_pass", open_pm([Budget(max=50.0, currency="USD")]), closed_pm(), ctx=MandateContext(total_amount=0))
    add("budget_over", open_pm([Budget(max=50.0, currency="USD")]), closed_pm(), ctx=MandateContext(total_amount=4500))
    add("budget_currency", open_pm([Budget(max=50.0, currency="EUR")]), closed_pm(), ctx=MandateContext(total_amount=0))

    # execution_date (ISO strings, lexical compare)
    ed = ExecutionDate(not_before="2026-01-01", not_after="2026-12-31")
    add("execution_date_pass", open_pm([ed]), closed_pm(execution_date="2026-06-01"))
    add("execution_date_before", open_pm([ed]), closed_pm(execution_date="2025-01-01"))
    add("execution_date_after", open_pm([ed]), closed_pm(execution_date="2027-01-01"))

    # payment.reference (binds to an open checkout hash)
    add("reference_pass", open_pm([PaymentReference(conditional_transaction_id="HASH123")]), closed_pm(), hash="HASH123")
    add("reference_mismatch", open_pm([PaymentReference(conditional_transaction_id="HASH123")]), closed_pm(), hash="OTHER")
    add("reference_missing_hash", open_pm([PaymentReference(conditional_transaction_id="HASH123")]), closed_pm())

    # agent_recurrence (requires amount_range + budget present)
    rec = AgentRecurrence(frequency=Frequency.MONTHLY, max_occurrences=3)
    full = [rec, AR(max=5000), Budget(max=50.0, currency="USD")]
    add("recurrence_pass", open_pm(full), closed_pm(), ctx=MandateContext(total_uses=1, total_amount=0))
    add("recurrence_exceeded", open_pm(full), closed_pm(), ctx=MandateContext(total_uses=3, total_amount=0))
    add("recurrence_requires_amount_budget", open_pm([rec]), closed_pm(), ctx=MandateContext(total_uses=0))

    # pre-set claims (open mandate pins a field the closed mandate must keep)
    add("preset_payee_mismatch", open_pm([], payee=Merchant(id="other", name="Other")), closed_pm())
    add("preset_amount_mismatch", open_pm([], payment_amount=Amount(amount=999, currency="USD")), closed_pm())

    # ── Checkout constraints ──
    def checkout(merchant=None, items=None):
        return Checkout(id="co_1", merchant=merchant, line_items=items or [], status=Status.completed,
                        currency="USD", totals=[Total(type="total", amount=0)],
                        links=[Link(type="self", url="https://shop.example/checkout")])

    def li(sku, qty):
        return LineItem(id=f"li_{sku}", item=Item(id=sku, title=sku, price=0), quantity=qty,
                        totals=[Total(type="total", amount=0)])

    def req(rid, acceptable, qty):  # acceptable=[] → wildcard
        return LineItemRequirements(id=rid, acceptable_items=[ReqItem(id=a, title=a) for a in acceptable], quantity=qty)

    def open_cm(constraints):
        return OpenCheckoutMandate(constraints=constraints, cnf=CNF)

    def add_co(name, om, co):
        violations = check_checkout_constraints(om, co)
        co_vectors.append({
            "name": name,
            "open": om.model_dump(mode="json", by_alias=True, exclude_none=True),
            "checkout": co.model_dump(mode="json", by_alias=True, exclude_none=True),
            "ap2Violations": violations,
            "valid": len(violations) == 0,
        })

    SHOP = Merchant(id="s-1", name="Shop", website="shop.example")
    add_co("merchants_pass", open_cm([AllowedMerchants(allowed=[SHOP])]), checkout(merchant=SHOP))
    add_co("merchants_fail", open_cm([AllowedMerchants(allowed=[Merchant(id="other", name="Other")])]), checkout(merchant=SHOP))
    add_co("merchants_missing", open_cm([AllowedMerchants(allowed=[SHOP])]), checkout(merchant=None))

    add_co("line_items_simple_pass", open_cm([LineItems(items=[req("r1", ["A"], 1)])]), checkout(items=[li("A", 1)]))
    add_co("line_items_degree1_pass", open_cm([LineItems(items=[req("r1", ["A"], 1), req("r2", ["B"], 1)])]),
           checkout(items=[li("A", 1), li("B", 1)]))
    add_co("line_items_not_acceptable", open_cm([LineItems(items=[req("r1", ["A"], 1)])]), checkout(items=[li("B", 1)]))
    add_co("line_items_oversupply", open_cm([LineItems(items=[req("r1", ["A"], 1)])]), checkout(items=[li("A", 2)]))
    add_co("line_items_wildcard_pass", open_cm([LineItems(items=[req("r1", [], 5)])]), checkout(items=[li("A", 2), li("B", 1)]))
    # complex (degree>1) → exercises the max-flow path
    add_co("line_items_complex_pass", open_cm([LineItems(items=[req("r1", ["A", "B"], 1), req("r2", ["B", "C"], 1)])]),
           checkout(items=[li("B", 2)]))
    add_co("line_items_complex_fail", open_cm([LineItems(items=[req("r1", ["A", "B"], 1), req("r2", ["B", "C"], 1)])]),
           checkout(items=[li("B", 3)]))
    add_co("line_items_empty_cart", open_cm([LineItems(items=[req("r1", ["A"], 1)])]), checkout(items=[]))

    # ── P5c: checkout-chain (self-computed checkout_hash, H6) + receipt reference ──
    checkout_chains: list[dict] = []
    receipt_refs: list[dict] = []

    def checkout_jwt_of(co) -> str:
        hdr = b64url_encode(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
        pl = b64url_encode(json.dumps(co.model_dump(mode="json", by_alias=True, exclude_none=True)).encode())
        return f"{hdr}.{pl}.sig"

    def add_checkout_chain(name, om, co, *, tamper_hash=False):
        cjwt = checkout_jwt_of(co)
        chash = compute_sha256_b64url(cjwt)
        if tamper_hash:
            chash = chash[:-1] + ("A" if chash[-1] != "A" else "B")
        closed = {"vct": "mandate.checkout.1", "checkout_jwt": cjwt, "checkout_hash": chash}
        open_dict = om.model_dump(mode="json", by_alias=True, exclude_none=True)
        # AP2's CheckoutMandateChain.verify = constraints only (it does NOT
        # self-compute checkout_hash; that is our H6 hardening).
        ap2_violations = CheckoutMandateChain.parse([open_dict, closed]).verify(checkout_jwt=cjwt)
        checkout_chains.append({
            "name": name, "open": open_dict, "closed": closed,
            "ap2Violations": ap2_violations, "tamperHash": tamper_hash,
        })

    add_checkout_chain("cc_valid", open_cm([AllowedMerchants(allowed=[SHOP]), LineItems(items=[req("r1", ["A"], 1)])]),
                       checkout(merchant=SHOP, items=[li("A", 1)]))
    add_checkout_chain("cc_constraint_fail", open_cm([AllowedMerchants(allowed=[Merchant(id="other", name="Other")])]),
                       checkout(merchant=SHOP, items=[li("A", 1)]))
    add_checkout_chain("cc_tampered_hash", open_cm([AllowedMerchants(allowed=[SHOP])]),
                       checkout(merchant=SHOP, items=[li("A", 1)]), tamper_hash=True)

    # Receipt reference = sd_hash of the final SD-JWT segment, for each valid chain.
    for cv in json.loads((HERE / "ap2-vectors.json").read_text()):
        if cv["expect"] != "valid":
            continue
        segs = cv["chain"].split("~~")
        last = common.parse_token(_canonical_chain_segment(segs[-1], len(segs) - 1, len(segs)))
        receipt_refs.append({"name": cv["name"], "chain": cv["chain"], "ap2Reference": common.compute_sd_hash(last)})

    LINK_OUT.write_text(json.dumps({"checkoutChains": checkout_chains, "receiptReferences": receipt_refs}, indent=2) + "\n")

    OUT.write_text(json.dumps(vectors, indent=2) + "\n")
    CO_OUT.write_text(json.dumps(co_vectors, indent=2) + "\n")
    print(f"wrote {len(vectors)} payment + {len(co_vectors)} checkout constraint + "
          f"{len(checkout_chains)} checkout-chain + {len(receipt_refs)} receipt-ref vectors")
    for v in vectors + co_vectors:
        print(f"  - {v['name']}: violations={len(v['ap2Violations'])} valid={v['valid']}")


if __name__ == "__main__":
    main()
