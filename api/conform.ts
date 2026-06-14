/**
 * GET /api/conform?target=<url> — run the chain vectors against a target
 * verifier endpoint (CONTRACT.md), server-side, and return a JSON report.
 * Defaults to this deployment's own /api/verify-chain (the reference).
 * Core logic + SSRF guard + contract-detection live in ../lib/run-http.ts.
 */
import { conform } from "../lib/run-http.js";

interface Req {
  query?: Record<string, string | string[] | undefined>;
  headers?: Record<string, string | string[] | undefined>;
}
interface Res {
  setHeader(k: string, v: string): void;
  status(code: number): Res;
  json(body: unknown): void;
}

const one = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);

export default async function handler(req: Req, res: Res): Promise<void> {
  res.setHeader("Access-Control-Allow-Origin", "*");
  const proto = one(req.headers?.["x-forwarded-proto"]) ?? "https";
  const host = one(req.headers?.["host"]) ?? "localhost:3000";
  const report = await conform(one(req.query?.["target"]), `${proto}://${host}`, host);
  res.status(report.status === "BLOCKED" ? 400 : 200).json(report);
}
