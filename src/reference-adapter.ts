/**
 * Reference adapter — backs the conformance suite with `@goodmeta/agent-verifier`,
 * a byte-exact port of AP2's reference SDK. This is one concrete implementation
 * of `Ap2VerifierAdapter`; the suite itself is implementation-agnostic.
 */
import { Buffer } from "node:buffer";
import { X509Certificate } from "node:crypto";
import { ap2, verifyReceipt, type JWK } from "@goodmeta/agent-verifier";
import type {
  Ap2VerifierAdapter,
  ChainVerifyInput,
  Payloads,
  ReceiptVerifyInput,
  SegmentHashes,
} from "./adapter.js";

type KeyOrProvider = Parameters<typeof ap2.verifyChain>[1];

// Required receipt fields, from AP2's machine schemas @ e1ea56d
// (code/sdk/schemas/ap2/{payment,checkout}_receipt.json: `required` + the
// `oneOf` Success/Error branches). agent-verifier verifies the signature only, so
// the field rules live here.
const RECEIPT_STATUS = ["Success", "Error"] as const;
const RECEIPT_REQUIRED = {
  payment: ["status", "iss", "iat", "reference", "payment_id"],
  checkout: ["status", "iss", "iat", "reference"],
} as const;
const RECEIPT_REQUIRED_BY_STATUS = {
  payment: { Success: ["psp_confirmation_id", "network_confirmation_id"], Error: ["error", "error_description"] },
  checkout: { Success: ["order_id"], Error: ["error", "error_description"] },
} as const;

async function verifyAp2Receipt(input: ReceiptVerifyInput): Promise<void> {
  const res = await verifyReceipt<Record<string, unknown>>(input.receiptJwt, input.issuerPublicKey as JWK);
  if (!res.valid || !res.payload) throw new Error(`receipt signature: ${res.error ?? "invalid"}`);
  const r = res.payload;
  const status = r.status;
  if (!RECEIPT_STATUS.includes(status as (typeof RECEIPT_STATUS)[number])) {
    throw new Error(`receipt status must be one of ${RECEIPT_STATUS.join("|")}`);
  }
  const required = [
    ...RECEIPT_REQUIRED[input.kind],
    ...RECEIPT_REQUIRED_BY_STATUS[input.kind][status as (typeof RECEIPT_STATUS)[number]],
  ];
  const missing = required.filter((f) => r[f] === undefined || r[f] === null);
  if (missing.length) throw new Error(`receipt missing required field(s): ${missing.join(", ")}`);
  if (!Number.isInteger(r.iat)) throw new Error("receipt iat must be an integer");
  const expected = ap2.receiptReference(input.mandateChain);
  if (r.reference !== expected) throw new Error("receipt reference does not match the closed mandate");
}

export const referenceAdapter: Ap2VerifierAdapter = {
  async verifyChain(input: ChainVerifyInput): Promise<Payloads> {
    const tokens = ap2.splitChain(input.chain);
    let keyOrProvider: KeyOrProvider;
    if (input.trustedRoots !== undefined) {
      const trustedRoots = input.trustedRoots.map((b) => new X509Certificate(Buffer.from(b, "base64url")));
      keyOrProvider = ap2.x5cOrKidProvider({
        trustedRoots,
        currentTime: new Date(input.currentTimeUnix * 1000),
      });
    } else {
      keyOrProvider = input.rootKey as unknown as KeyOrProvider;
    }
    const payloads = await ap2.verifyChain(tokens, keyOrProvider, {
      expectedAud: input.expectedAud,
      expectedNonce: input.expectedNonce,
      currentTime: input.currentTimeUnix,
    });
    return payloads as Payloads;
  },

  checkPaymentConstraints(input) {
    const open = ap2.OpenPaymentMandateSchema.parse(input.open);
    const closed = ap2.PaymentMandateSchema.parse(input.closed);
    return ap2.checkPaymentConstraints(open, closed, {
      openCheckoutHash: input.openCheckoutHash ?? undefined,
      mandateContext: input.context
        ? { total_amount: input.context.total_amount, total_uses: input.context.total_uses }
        : undefined,
      requiredConstraints: input.requiredConstraints,
    });
  },

  checkCheckoutConstraints(input) {
    const open = ap2.OpenCheckoutMandateSchema.parse(input.open);
    const checkout = ap2.CheckoutSchema.parse(input.checkout);
    return ap2.checkCheckoutConstraints(open, checkout);
  },

  verifyCheckoutChain(input) {
    const chain = ap2.parseCheckoutChain([input.open, input.closed]);
    return ap2.verifyCheckoutChain(chain);
  },

  receiptReference(chain) {
    return ap2.receiptReference(chain);
  },

  verifyReceipt: verifyAp2Receipt,

  segmentHashes(chain): SegmentHashes[] {
    return ap2.splitChain(chain).map((t) => ({
      issuerJwt: t.issuerJwt,
      disclosures: t.disclosures,
      kbJwt: t.kbJwt,
      sdAlg: t.sdAlg ?? null,
      sdJwt: t.sdJwt,
      canonical: t.canonical,
      sdHash: ap2.computeSdHash(t),
      issuerJwtHash: ap2.computeIssuerJwtHash(t),
      disclosureDigests: Object.fromEntries(
        t.disclosures.map((d) => [d, ap2.computeDisclosureDigest(d, t.sdAlg)]),
      ),
    }));
  },
};
