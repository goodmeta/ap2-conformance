/**
 * GET /api/badge?target=<url> — a live, verifiable conformance badge (SVG).
 * It RE-RUNS the chain vectors against the target server-side, so the badge
 * can't be faked (it's computed, not self-asserted) and is always current.
 * Cached at the edge so repeated README loads don't re-run every time.
 *
 *   ![AP2 conformance](https://ap2-conformance.vercel.app/api/badge?target=<your-url>)
 */
import { conform, type Report } from "../lib/run-http.js";

interface Req {
  query?: Record<string, string | string[] | undefined>;
  headers?: Record<string, string | string[] | undefined>;
}
interface Res {
  setHeader(k: string, v: string): void;
  status(code: number): Res;
  send(body: string): void;
}

const one = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);
const esc = (s: string): string => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

function valueAndColor(r: Report): { value: string; color: string } {
  switch (r.status) {
    case "CONFORMANT":
      return { value: `${r.core.passed}/${r.core.total} ✓`, color: "#2ea043" };
    case "NON_CONFORMANT":
      return { value: `${r.core.passed}/${r.core.total} ✗`, color: "#d1242f" };
    case "BLOCKED":
      return { value: "blocked", color: "#8b949e" };
    default:
      return { value: "no contract", color: "#9a6700" };
  }
}

function badgeSvg(label: string, value: string, color: string): string {
  const w = (t: string) => Math.round(t.length * 6.6 + 14);
  const lw = w(label);
  const vw = w(value);
  const total = lw + vw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${esc(label)}: ${esc(value)}">
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="${lw}" height="20" fill="#33333b"/>
<rect x="${lw}" width="${vw}" height="20" fill="${color}"/>
<rect width="${total}" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="${lw / 2}" y="14">${esc(label)}</text>
<text x="${lw + vw / 2}" y="14">${esc(value)}</text>
</g>
</svg>`;
}

export default async function handler(req: Req, res: Res): Promise<void> {
  const proto = one(req.headers?.["x-forwarded-proto"]) ?? "https";
  const host = one(req.headers?.["host"]) ?? "localhost:3000";
  let report: Report;
  try {
    report = await conform(one(req.query?.["target"]), `${proto}://${host}`, host);
  } catch {
    report = { status: "BLOCKED" } as Report;
  }
  const { value, color } = valueAndColor(report);
  res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=0, s-maxage=600, stale-while-revalidate=86400");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.status(200).send(badgeSvg("AP2 conformance", value, color));
}
