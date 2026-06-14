/**
 * Reference conformance endpoint — implements CONTRACT.md on top of
 * @goodmeta/agent-verifier. CORS-open, no auth, "conformance mode": it trusts
 * the root key the request supplies and evaluates at the request's clock. This
 * is the URL the microsite prefills; swap in your own verifier to compare.
 */
import { Buffer } from "node:buffer";
import { X509Certificate } from "node:crypto";
import { ap2 } from "@goodmeta/agent-verifier";

// Minimal Vercel Node handler types (avoids pinning @vercel/node).
interface Req {
  method?: string;
  body?: unknown;
}
interface Res {
  setHeader(k: string, v: string): void;
  status(code: number): Res;
  json(body: unknown): void;
  end(): void;
}

function cors(res: Res): void {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type");
}

type KeyOrProvider = Parameters<typeof ap2.verifyChain>[1];

export default async function handler(req: Req, res: Res): Promise<void> {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "POST only" });

  try {
    const body = (typeof req.body === "string" ? JSON.parse(req.body) : req.body) as {
      chain?: string;
      rootKey?: Record<string, unknown> | null;
      trustedRoots?: string[] | null;
      currentTimeUnix?: number;
      expectedAud?: string;
      expectedNonce?: string;
    };
    if (!body || typeof body.chain !== "string") {
      return res.status(400).json({ ok: false, error: "missing 'chain'" });
    }

    const tokens = ap2.splitChain(body.chain);
    let keyOrProvider: KeyOrProvider;
    if (body.trustedRoots != null) {
      const roots = body.trustedRoots.map((b) => new X509Certificate(Buffer.from(b, "base64url")));
      keyOrProvider = ap2.x5cOrKidProvider({
        trustedRoots: roots,
        currentTime: body.currentTimeUnix != null ? new Date(body.currentTimeUnix * 1000) : undefined,
      });
    } else {
      keyOrProvider = body.rootKey as unknown as KeyOrProvider;
    }

    const payloads = await ap2.verifyChain(tokens, keyOrProvider, {
      expectedAud: body.expectedAud,
      expectedNonce: body.expectedNonce,
      currentTime: body.currentTimeUnix,
    });
    return res.status(200).json({ ok: true, payloads });
  } catch (e) {
    return res.status(200).json({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
}
