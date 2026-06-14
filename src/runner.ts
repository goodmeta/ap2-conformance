/**
 * The conformance runner. Drives every vector category through an
 * `Ap2VerifierAdapter` and reports two profiles:
 *
 *   - CORE      — behaviour where AP2's own reference SDK agrees. A conformant
 *                 AP2 verifier MUST pass all of these.
 *   - HARDENING — cases where the reference verifier is deliberately STRICTER
 *                 than AP2 (AP2 accepts; a hardened verifier rejects). These are
 *                 informational. Failing them does NOT mean non-conformant — it
 *                 means "this implementation follows AP2's literal behaviour."
 *
 * Keeping these separate is the point: a neutral conformance suite must never
 * fail a spec-faithful implementation for one vendor's extra strictness.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { Ap2VerifierAdapter } from "./adapter.js";

/** The frozen instant the vectors were minted at (AP2 SDK `FROZEN_NOW`). Using
 * it as the evaluation clock makes the suite reproducible regardless of when it
 * runs (no wall-clock dependence). */
export const CANONICAL_TIME_UNIX = 1780000000;

const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "vectors");
const load = (file: string): unknown => JSON.parse(readFileSync(join(VECTORS_DIR, file), "utf8"));

export type Profile = "core" | "hardening";

export interface VectorResult {
  category: string;
  name: string;
  profile: Profile;
  passed: boolean;
  detail?: string;
}

export interface RunReport {
  results: VectorResult[];
  core: { passed: number; total: number };
  hardening: { passed: number; total: number };
  /** True iff every CORE vector passed. The pass/fail of the whole suite. */
  conformant: boolean;
}

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// AP2 embeds a Python object `repr` in exactly these two payment-constraint
// messages, so they are matched by violation COUNT, not bytes. Every other
// message is asserted byte-for-byte against AP2's output.
const REPR_ONLY = new Set(["allowed_pisps_fail", "preset_amount_mismatch"]);

interface ChainVec {
  name: string;
  chain: string;
  kind?: string;
  rootKey?: Record<string, unknown>;
  x5cTrustedRoots?: string[];
  expectedAud: string;
  expectedNonce: string;
  expect: "valid" | "reject";
  hardening?: boolean;
  expectedPayloads?: Record<string, unknown>[];
}

async function runChain(a: Ap2VerifierAdapter): Promise<VectorResult[]> {
  const vectors = load("chain.json") as ChainVec[];
  const out: VectorResult[] = [];
  for (const v of vectors) {
    const profile: Profile = v.hardening ? "hardening" : "core";
    const isX5c = v.kind === "x5c";
    const input = {
      chain: v.chain,
      rootKey: isX5c ? undefined : v.rootKey,
      trustedRoots: isX5c ? v.x5cTrustedRoots ?? [] : undefined,
      currentTimeUnix: CANONICAL_TIME_UNIX,
      expectedAud: v.expectedAud,
      expectedNonce: v.expectedNonce,
    };
    let passed = false;
    let detail: string | undefined;
    if (v.expect === "valid") {
      try {
        const payloads = await a.verifyChain(input);
        passed = isDeepStrictEqual(payloads, v.expectedPayloads);
        if (!passed) detail = "per-hop payloads differ from AP2 reference output";
      } catch (e) {
        detail = `threw on a valid vector: ${errMsg(e)}`;
      }
    } else {
      try {
        await a.verifyChain(input);
        detail = "accepted a chain that must be rejected";
      } catch {
        passed = true;
      }
    }
    out.push({ category: "chain", name: v.name, profile, passed, detail: passed ? undefined : detail });
  }
  return out;
}

interface PaymentCV {
  name: string;
  open: unknown;
  closed: unknown;
  openCheckoutHash: string | null;
  context: { total_amount: number; total_uses: number } | null;
  ap2Violations: string[];
  valid: boolean;
}

function runPaymentConstraints(a: Ap2VerifierAdapter): VectorResult[] {
  const vectors = load("payment-constraints.json") as PaymentCV[];
  return vectors.map((v) => {
    let passed = false;
    let detail: string | undefined;
    try {
      const violations = a.checkPaymentConstraints({
        open: v.open,
        closed: v.closed,
        openCheckoutHash: v.openCheckoutHash,
        context: v.context,
      });
      const validParity = (violations.length === 0) === v.valid;
      const msgParity = REPR_ONLY.has(v.name)
        ? violations.length === v.ap2Violations.length
        : isDeepStrictEqual(violations, v.ap2Violations);
      passed = validParity && msgParity;
      if (!passed) detail = `got ${JSON.stringify(violations)} vs AP2 ${JSON.stringify(v.ap2Violations)}`;
    } catch (e) {
      detail = `threw: ${errMsg(e)}`;
    }
    return { category: "payment-constraints", name: v.name, profile: "core" as Profile, passed, detail: passed ? undefined : detail };
  });
}

interface CheckoutCV {
  name: string;
  open: unknown;
  checkout: unknown;
  ap2Violations: string[];
  valid: boolean;
}

function runCheckoutConstraints(a: Ap2VerifierAdapter): VectorResult[] {
  const vectors = load("checkout-constraints.json") as CheckoutCV[];
  return vectors.map((v) => {
    let passed = false;
    let detail: string | undefined;
    try {
      const violations = a.checkCheckoutConstraints({ open: v.open, checkout: v.checkout });
      const validParity = (violations.length === 0) === v.valid;
      const msgParity = isDeepStrictEqual(violations, v.ap2Violations);
      passed = validParity && msgParity;
      if (!passed) detail = `got ${JSON.stringify(violations)} vs AP2 ${JSON.stringify(v.ap2Violations)}`;
    } catch (e) {
      detail = `threw: ${errMsg(e)}`;
    }
    return { category: "checkout-constraints", name: v.name, profile: "core" as Profile, passed, detail: passed ? undefined : detail };
  });
}

interface LinkageFile {
  checkoutChains: { name: string; open: unknown; closed: unknown; ap2Violations: string[]; tamperHash: boolean }[];
  receiptReferences: { name: string; chain: string; ap2Reference: string }[];
}

function runCheckoutChains(a: Ap2VerifierAdapter, link: LinkageFile): VectorResult[] {
  return link.checkoutChains.map((cc) => {
    const profile: Profile = cc.tamperHash ? "hardening" : "core";
    let passed = false;
    let detail: string | undefined;
    try {
      const violations = a.verifyCheckoutChain({ open: cc.open, closed: cc.closed });
      if (cc.tamperHash) {
        // AP2 trusts the claimed checkout_hash and accepts (0 violations). A
        // hardened verifier self-computes it and finds exactly one mismatch.
        passed = violations.length === 1 && /checkout_hash mismatch/i.test(violations[0]);
        if (!passed) detail = `expected a self-computed checkout_hash mismatch; got ${JSON.stringify(violations)}`;
      } else {
        passed = isDeepStrictEqual(violations, cc.ap2Violations);
        if (!passed) detail = `got ${JSON.stringify(violations)} vs AP2 ${JSON.stringify(cc.ap2Violations)}`;
      }
    } catch (e) {
      detail = `threw: ${errMsg(e)}`;
    }
    return { category: "checkout-chain", name: cc.name, profile, passed, detail: passed ? undefined : detail };
  });
}

function runReceiptReferences(a: Ap2VerifierAdapter, link: LinkageFile): VectorResult[] {
  return link.receiptReferences.map((rr) => {
    let passed = false;
    let detail: string | undefined;
    try {
      const ref = a.receiptReference(rr.chain);
      passed = ref === rr.ap2Reference;
      if (!passed) detail = `got ${ref} vs AP2 ${rr.ap2Reference}`;
    } catch (e) {
      detail = `threw: ${errMsg(e)}`;
    }
    return { category: "receipt-reference", name: rr.name, profile: "core" as Profile, passed, detail: passed ? undefined : detail };
  });
}

interface HashPairsFile {
  rawSplitOnDoubleTilde: string[];
  segments: Record<string, unknown>[];
}

const SEGMENT_FIELDS = [
  "issuerJwt",
  "disclosures",
  "kbJwt",
  "sdAlg",
  "sdJwt",
  "canonical",
  "sdHash",
  "issuerJwtHash",
  "disclosureDigests",
] as const;

function runHashPairs(a: Ap2VerifierAdapter): VectorResult[] {
  if (!a.segmentHashes) return []; // optional category — skipped when unimplemented
  const hp = load("hash-pairs.json") as HashPairsFile;
  const chain = hp.rawSplitOnDoubleTilde.join("~~");
  let got: Record<string, unknown>[];
  try {
    got = a.segmentHashes(chain) as unknown as Record<string, unknown>[];
  } catch (e) {
    return [{ category: "hash-pairs", name: "segmentHashes", profile: "core", passed: false, detail: `threw: ${errMsg(e)}` }];
  }
  return hp.segments.map((exp, i) => {
    const g = got[i];
    const passed = !!g && SEGMENT_FIELDS.every((f) => isDeepStrictEqual(g[f], exp[f]));
    return {
      category: "hash-pairs",
      name: `segment[${i}]`,
      profile: "core" as Profile,
      passed,
      detail: passed ? undefined : `byte-exact field mismatch in segment ${i}`,
    };
  });
}

export async function runConformance(adapter: Ap2VerifierAdapter): Promise<RunReport> {
  const link = load("linkage.json") as LinkageFile;
  const results: VectorResult[] = [
    ...(await runChain(adapter)),
    ...runPaymentConstraints(adapter),
    ...runCheckoutConstraints(adapter),
    ...runCheckoutChains(adapter, link),
    ...runReceiptReferences(adapter, link),
    ...runHashPairs(adapter),
  ];
  const core = results.filter((r) => r.profile === "core");
  const hardening = results.filter((r) => r.profile === "hardening");
  return {
    results,
    core: { passed: core.filter((r) => r.passed).length, total: core.length },
    hardening: { passed: hardening.filter((r) => r.passed).length, total: hardening.length },
    conformant: core.every((r) => r.passed),
  };
}
