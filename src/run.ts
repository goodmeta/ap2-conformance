/**
 * CLI entry: run the conformance suite against the reference adapter, print a
 * grouped report, and exit non-zero if any CORE vector fails. This is what CI
 * runs and what an implementer runs to see their own verifier's result (swap in
 * their adapter).
 */
import { runConformance, type VectorResult } from "./runner.js";
import { referenceAdapter } from "./reference-adapter.js";

const report = await runConformance(referenceAdapter);

const byCategory = new Map<string, VectorResult[]>();
for (const r of report.results) {
  const arr = byCategory.get(r.category) ?? [];
  arr.push(r);
  byCategory.set(r.category, arr);
}

console.log("AP2 Conformance — reference adapter (@goodmeta/agent-verifier)");
console.log("vectors minted from AP2's own SDK @ e1ea56d; canonical clock 1780000000\n");

for (const [category, rs] of byCategory) {
  const core = rs.filter((r) => r.profile === "core");
  const hardening = rs.filter((r) => r.profile === "hardening");
  const corePass = core.filter((r) => r.passed).length;
  const hardPass = hardening.filter((r) => r.passed).length;
  const mark = core.every((r) => r.passed) ? "✓" : "✗";
  const hardTag = hardening.length ? ` · ${hardPass}/${hardening.length} hardening` : "";
  console.log(`  ${mark} ${category.padEnd(22)} ${corePass}/${core.length} core${hardTag}`);
}

const coreFailures = report.results.filter((r) => !r.passed && r.profile === "core");
if (coreFailures.length) {
  console.log("\nCORE FAILURES (these mean non-conformant):");
  for (const f of coreFailures) console.log(`  ✗ [${f.category}] ${f.name} — ${f.detail}`);
}

const hardeningMisses = report.results.filter((r) => !r.passed && r.profile === "hardening");
if (hardeningMisses.length) {
  console.log("\nHardening not matched (informational — impl follows AP2's literal behaviour, not a failure):");
  for (const f of hardeningMisses) console.log(`  · [${f.category}] ${f.name}`);
}

console.log(`\nCORE:      ${report.core.passed}/${report.core.total}  (must be 100% to be conformant)`);
console.log(`HARDENING: ${report.hardening.passed}/${report.hardening.total}  (optional, stricter-than-AP2)`);
console.log(report.conformant ? "\n✅ CONFORMANT — all core vectors pass" : "\n❌ NOT CONFORMANT — see core failures above");

process.exit(report.conformant ? 0 : 1);
