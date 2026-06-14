/**
 * @goodmeta/ap2-conformance
 *
 * Open, implementation-agnostic conformance vectors + runner for AP2 mandate
 * verification. Point your own verifier at it:
 *
 *   import { runConformance, type Ap2VerifierAdapter } from "@goodmeta/ap2-conformance";
 *   const report = await runConformance(myAdapter);
 *   if (!report.conformant) process.exit(1);
 *
 * Or run the bundled reference adapter (backed by @goodmeta/agent-verifier):
 *   npx @goodmeta/ap2-conformance   // → see src/run.ts
 */
export * from "./adapter.js";
export {
  runConformance,
  CANONICAL_TIME_UNIX,
  type Profile,
  type VectorResult,
  type RunReport,
} from "./runner.js";
export { referenceAdapter } from "./reference-adapter.js";
