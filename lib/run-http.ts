/**
 * Shared HTTP conformance runner — fires every `chain` vector at a target
 * verifier (CONTRACT.md), server-side. Used by both /api/conform (JSON report)
 * and /api/badge (SVG). Includes the SSRF guard + contract-detection.
 */
import chainVectors from "../vectors/chain.json" with { type: "json" };
import { lookup } from "node:dns/promises";

export const CANONICAL_TIME_UNIX = 1780000000;
const PER_CALL_TIMEOUT_MS = 7000;

export interface VectorResult {
  category: string;
  name: string;
  profile: "core" | "hardening";
  spoke: boolean;
  passed: boolean;
  accepted: boolean | null;
  detail?: string;
}

export interface Report {
  target: string;
  status: "CONFORMANT" | "NON_CONFORMANT" | "DID_NOT_IMPLEMENT_CONTRACT" | "BLOCKED";
  endpointSpeaksContract: boolean;
  spokeCount: number;
  totalVectors: number;
  note: string;
  error?: string;
  results: VectorResult[];
  core: { passed: number; total: number };
  hardening: { passed: number; total: number };
  conformant: boolean;
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

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

/** Loopback / private / link-local (incl. cloud metadata) IP literal. */
export function isPrivateIp(addr: string): boolean {
  const a = addr.toLowerCase().replace(/^\[|\]$/g, "");
  if (a === "::1" || a === "::") return true;
  if (a.startsWith("fe80") || a.startsWith("fc") || a.startsWith("fd")) return true;
  const mapped = a.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  const v4 = mapped ? mapped[1] : /^\d{1,3}(?:\.\d{1,3}){3}$/.test(a) ? a : null;
  if (!v4) return false;
  const p = v4.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [x, y] = p;
  if (x === 0 || x === 10 || x === 127) return true;
  if (x === 169 && y === 254) return true;
  if (x === 172 && y >= 16 && y <= 31) return true;
  if (x === 192 && y === 168) return true;
  if (x === 100 && y >= 64 && y <= 127) return true;
  return false;
}

export function resolveTarget(rawTarget: string | undefined, selfBase: string): string {
  let t = (rawTarget ?? "").trim();
  if (!t || t === "reference") return `${selfBase}/api/verify-chain`;
  if (t.startsWith("/")) return `${selfBase}${t}`;
  return t;
}

async function classifyTarget(target: string, selfHost: string): Promise<{ ok: boolean; reason?: string }> {
  let u: URL;
  try {
    u = new URL(target);
  } catch {
    return { ok: false, reason: "invalid URL" };
  }
  if (u.host === selfHost) return { ok: true };
  if (u.protocol !== "https:") return { ok: false, reason: "target must use https" };
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) return { ok: false, reason: "private host blocked" };
  if (isPrivateIp(host)) return { ok: false, reason: "private/loopback IP blocked" };
  try {
    const addrs = await lookup(host, { all: true });
    if (addrs.some((a) => isPrivateIp(a.address))) return { ok: false, reason: "host resolves to a private IP" };
  } catch {
    return { ok: false, reason: "host does not resolve" };
  }
  return { ok: true };
}

/** Resolve + SSRF-guard + run the chain vectors against `rawTarget`. */
export async function conform(rawTarget: string | undefined, selfBase: string, selfHost: string): Promise<Report> {
  const target = resolveTarget(rawTarget, selfBase);
  const guard = await classifyTarget(target, selfHost);
  if (!guard.ok) {
    return {
      target,
      status: "BLOCKED",
      error: `target rejected: ${guard.reason}`,
      endpointSpeaksContract: false,
      spokeCount: 0,
      totalVectors: 0,
      note: "Target was rejected by the SSRF guard.",
      results: [],
      core: { passed: 0, total: 0 },
      hardening: { passed: 0, total: 0 },
      conformant: false,
    };
  }

  const vectors = chainVectors as ChainVector[];
  const results: VectorResult[] = await Promise.all(
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
      const profile: "core" | "hardening" = v.hardening ? "hardening" : "core";
      let spoke = false;
      let passed = false;
      let accepted: boolean | null = null;
      let detail: string | undefined;
      try {
        const r = await fetch(target, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(reqBody),
          signal: AbortSignal.timeout(PER_CALL_TIMEOUT_MS),
        });
        let j: { ok?: unknown; payloads?: unknown; error?: string } | null = null;
        try {
          j = (await r.json()) as { ok?: unknown; payloads?: unknown; error?: string };
        } catch {
          j = null;
        }
        if (j && typeof j.ok === "boolean") {
          spoke = true;
          accepted = j.ok;
          if (v.expect === "valid") {
            passed = j.ok === true && deepEqual(j.payloads, v.expectedPayloads);
            if (!passed) detail = j.ok ? "accepted, but payloads differ from AP2" : `rejected a valid vector (${j.error ?? "no reason"})`;
          } else {
            passed = j.ok === false;
            if (!passed) detail = "accepted a vector that must be rejected";
          }
        } else {
          detail = r.ok ? "response was not the conformance shape { ok, payloads }" : `HTTP ${r.status} (not the conformance contract)`;
        }
      } catch (e) {
        detail = `request failed: ${errMsg(e)}`;
      }
      return { category: "chain", name: v.name, profile, spoke, passed, accepted, detail };
    }),
  );

  const spokeCount = results.filter((r) => r.spoke).length;
  const endpointSpeaksContract = spokeCount > 0;
  const core = results.filter((r) => r.profile === "core");
  const hard = results.filter((r) => r.profile === "hardening");
  const conformant = endpointSpeaksContract && core.every((r) => r.passed);
  const status = !endpointSpeaksContract ? "DID_NOT_IMPLEMENT_CONTRACT" : conformant ? "CONFORMANT" : "NON_CONFORMANT";

  return {
    target,
    status,
    endpointSpeaksContract,
    spokeCount,
    totalVectors: results.length,
    note: endpointSpeaksContract
      ? "HTTP runner covers the chain category only; the full 67-check suite runs in-process via the adapter."
      : "This URL never responded with the conformance contract — it isn't an AP2 verifier speaking CONTRACT.md (or it errored / timed out).",
    results,
    core: { passed: core.filter((r) => r.passed).length, total: core.length },
    hardening: { passed: hard.filter((r) => r.passed).length, total: hard.length },
    conformant,
  };
}
