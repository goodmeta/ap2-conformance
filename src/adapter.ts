/**
 * Implementation-agnostic adapter for AP2 mandate verification.
 *
 * To run the conformance suite against YOUR AP2 verifier, implement this
 * interface and pass it to `runConformance(adapter)`. The reference adapter
 * (`reference-adapter.ts`, backed by `@goodmeta/agent-verifier`) shows one
 * concrete implementation.
 *
 * The types here are deliberately plain (no dependency on any verifier library)
 * so an implementation in any language/runtime can mirror the contract.
 */

/** A parsed JSON value from a vector (mandate payloads are plain objects). */
export type Json = unknown;

/** Per-hop effective payloads returned by a successful chain verification. */
export type Payloads = Record<string, unknown>[];

export interface ChainVerifyInput {
  /** The compact dSD-JWT chain (`~~`-joined segments). */
  chain: string;
  /** Root issuer public JWK (the `kid`/direct-key trust path). */
  rootKey?: Record<string, unknown>;
  /** Trusted root CA certs as base64url-DER strings (the `x5c` trust path). */
  trustedRoots?: string[];
  /**
   * Canonical evaluation time, Unix seconds. Drives BOTH the chain `iat`/`exp`
   * checks and (for the x5c path) certificate validity windows, so the suite is
   * reproducible regardless of wall-clock.
   */
  currentTimeUnix: number;
  /** Merchant-issued audience the terminal hop MUST be bound to. */
  expectedAud: string;
  /** Merchant-issued nonce the terminal hop MUST be bound to. */
  expectedNonce: string;
}

/** Per-segment canonicalization + binding hashes (the `hash-pairs` category). */
export interface SegmentHashes {
  issuerJwt: string;
  disclosures: string[];
  kbJwt: string | null;
  sdAlg: string | null;
  sdJwt: string;
  canonical: string;
  sdHash: string;
  issuerJwtHash: string;
  disclosureDigests: Record<string, string>;
}

export interface Ap2VerifierAdapter {
  /**
   * Verify a dSD-JWT delegation chain. On success, return the per-hop effective
   * payloads `[open, …, closed]`. On ANY rejection (bad signature, binding,
   * aud/nonce, trust, expiry, …) this MUST throw.
   */
  verifyChain(input: ChainVerifyInput): Promise<Payloads>;

  /**
   * Evaluate closed-world payment constraints. Return the list of violation
   * strings (empty = the closed mandate satisfies the open mandate's
   * constraints). Unknown constraints MUST count as a violation, never a skip.
   */
  checkPaymentConstraints(input: {
    open: Json;
    closed: Json;
    openCheckoutHash?: string | null;
    context?: { total_amount: number; total_uses: number } | null;
  }): string[];

  /** Evaluate closed-world checkout constraints. Return violation strings. */
  checkCheckoutConstraints(input: { open: Json; checkout: Json }): string[];

  /**
   * Verify a checkout chain's linkage (constraints + checkout_hash). Return
   * violation strings. A conformant verifier SHOULD independently recompute the
   * checkout_hash rather than trust the claimed value.
   */
  verifyCheckoutChain(input: { open: Json; closed: Json }): string[];

  /**
   * The Mandate Receipt `reference`: base64url hash of the FINAL SD-JWT segment
   * (computed like `sd_hash`, incl. disclosures), per AUTH-17.
   */
  receiptReference(chain: string): string;

  /**
   * OPTIONAL — per-segment canonicalization + binding hashes. Implement to run
   * the low-level `hash-pairs` category; omit to skip it.
   */
  segmentHashes?(chain: string): SegmentHashes[];
}
