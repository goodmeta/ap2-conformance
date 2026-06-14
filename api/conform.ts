/**
 * Conformance runner — fires every `chain` vector at a target verifier endpoint
 * (which implements CONTRACT.md), SERVER-SIDE, so it works against any URL
 * regardless of the target's CORS. Returns a live report the microsite renders.
 *
 *   GET /api/conform?target=https://your-verifier.example/verify
 *
 * With no target it defaults to this deployment's own /api/verify-chain (the
 * reference), so the prefilled "Run" shows a live green result.
 */
import chainVectors from "../vectors/chain.json" with { type: "json" };

const CANONICAL_TIME_UNIX = 1780000000;
const PER_CALL_TIMEOUT_MS = 7000;

interface Req {
  query?: Record<string, string | string[] | undefined>;
  headers?: Record<string, string | string[] | undefined>;
}
interface Res {
  setHeader(k: string, v: string): void;
  status(code: number): Res;
  json(body: unknown): void;
}

interface ChainVector {
  name: string;
  chain: string;
  kind?: string;
  rootKey?: Record<string, unknown>;
  x5cTrustedRoots?: string[];
  expectedAud: string;
  expectedNonce: string;
  expect: "valid" | "reject";
  hardening?: boolean;
  expectedPayloads?: unknown;
}

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const one = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);

// Order-independent deep equality for JSON values.
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

export default async function handler(req: Req, res: Res): Promise<void> {
  res.setHeader("Access-Control-Allow-Origin", "*");

  const proto = one(req.headers?.["x-forwarded-proto"]) ?? "https";
  const host = one(req.headers?.["host"]) ?? "localhost:3000";
  const selfBase = `${proto}://${host}`;

  let target = one(req.query?.["target"])?.trim();
  if (!target || target === "reference") target = `${selfBase}/api/verify-chain`;
  else if (target.startsWith("/")) target = `${selfBase}${target}`;

  const vectors = chainVectors as ChainVector[];

  const results = await Promise.all(
    vectors.map(async (v) => {
      const isX5c = v.kind === "x5c";
      const reqBody = {
        chain: v.chain,
        rootKey: isX5c ? null : v.rootKey,
        trustedRoots: isX5c ? v.x5cTrustedRoots ?? [] : null,
        currentTimeUnix: CANONICAL_TIME_UNIX,
        expectedAud: v.expectedAud,
        expectedNonce: v.expectedNonce,
      };
      const profile = v.hardening ? "hardening" : "core";
      let passed = false;
      let accepted: boolean | null = null;
      let detail: string | undefined;
      try {
        const r = await fetch(target as string, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(reqBody),
          signal: AbortSignal.timeout(PER_CALL_TIMEOUT_MS),
        });
        const j = (await r.json()) as { ok?: boolean; payloads?: unknown; error?: string };
        accepted = j.ok === true;
        if (v.expect === "valid") {
          passed = j.ok === true && deepEqual(j.payloads, v.expectedPayloads);
          if (!passed) detail = j.ok ? "accepted, but payloads differ from AP2" : `rejected a valid vector (${j.error ?? "no reason"})`;
        } else {
          passed = j.ok === false;
          if (!passed) detail = "accepted a vector that must be rejected";
        }
      } catch (e) {
        detail = `request failed: ${errMsg(e)}`;
      }
      return { category: "chain", name: v.name, profile, passed, accepted, detail };
    }),
  );

  const core = results.filter((r) => r.profile === "core");
  const hard = results.filter((r) => r.profile === "hardening");
  res.status(200).json({
    target,
    note: "HTTP runner covers the chain category only; the full 67-check suite runs in-process via the adapter.",
    results,
    core: { passed: core.filter((r) => r.passed).length, total: core.length },
    hardening: { passed: hard.filter((r) => r.passed).length, total: hard.length },
    conformant: core.every((r) => r.passed),
  });
}
