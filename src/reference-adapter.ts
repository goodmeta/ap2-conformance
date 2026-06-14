/**
 * Reference adapter — backs the conformance suite with `@goodmeta/agent-verifier`,
 * a byte-exact port of AP2's reference SDK. This is one concrete implementation
 * of `Ap2VerifierAdapter`; the suite itself is implementation-agnostic.
 */
import { Buffer } from "node:buffer";
import { X509Certificate } from "node:crypto";
import { ap2 } from "@goodmeta/agent-verifier";
import type { Ap2VerifierAdapter, ChainVerifyInput, Payloads, SegmentHashes } from "./adapter.js";

type KeyOrProvider = Parameters<typeof ap2.verifyChain>[1];

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
