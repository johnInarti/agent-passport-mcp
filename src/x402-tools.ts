/**
 * x402-tools — the x402 ⇄ MCP bridge.
 *
 * Surfaces every paid FractalAI x402 route as an AUTO-PAYABLE MCP tool with a SEMANTIC name (the
 * words an LLM would reach for during tool-selection — that description IS the discovery SEO).
 *
 * PAYMENT (the standard x402-over-MCP convention, built directly on MCP `_meta` — no third-party
 * coupling): an x402-aware client (a wallet-enabled agent in Claude/Cursor/ChatGPT) calls the tool,
 * gets back `isError:true` + `_meta["x402/payment-required"]` (the exact x402 `accepts[]` challenge),
 * signs an EIP-3009 authorization, and retries with the base64 payment in `_meta["x402/payment"]`.
 * We forward that verbatim to the route's `X-PAYMENT` header, so ALL of our D3-hardened settlement
 * (sovereign EIP-3009 verify+settle, per-route domain-separated ML-DSA-65 signatures, anti-replay,
 * verifiable receipts) is reused unchanged. On success we return the result + `_meta["x402/payment-
 * response"]` (settlement receipt). A plain `payment` string arg is ALSO accepted as a fallback for
 * clients that don't yet plumb `_meta`, so the tool is usable everywhere.
 *
 * HONESTY (Regla 4): the bridge invents nothing — it proxies to the live routes and relays exactly
 * what they return, including the honest scope of each proof. Prices are the real on-chain amounts.
 */
import { z } from "zod";
import { baseUrl } from "./passport.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Args = Record<string, any>;

interface X402Tool {
  name: string; // semantic MCP tool name
  route: string; // /api/x402/<route>
  priceUsd: string;
  title: string;
  description: string;
  inputSchema: Record<string, z.ZodTypeAny>;
  toBody: (a: Args) => Record<string, unknown>;
}

/** Drop undefined/null so we never send noise fields to a route. */
const clean = (o: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));

const PAY = {
  payment: z
    .string()
    .optional()
    .describe(
      "Optional base64 x402 X-PAYMENT (EIP-3009 exact-scheme payload, or {txHash}). x402-aware wallet " +
        'clients pass this automatically via _meta["x402/payment"] — set it explicitly only if your ' +
        "client does not plumb _meta. Omit on the first call to receive the payment challenge.",
    ),
};

const TOOLS: X402Tool[] = [
  {
    name: "witness_payment",
    route: "/api/x402/witness",
    priceUsd: "$0.005",
    title: "Witness an x402 payment settlement",
    description:
      "Obtain a FractalAI ML-DSA-65 attestation of a declared payment settlement. " +
      "The service checks the claimed transfer when a transaction is supplied. " +
      "Call without payment first for the current price and requirements. " +
      "Keep the exact request and payment authorization for recovery; this tool never retries payments. " +
      "Use the witness SDK to construct request_binding for bound requests. " +
      "An attestation does not prove the purchased content is true.",
    inputSchema: {
      seal_body: z.record(z.unknown()).describe("Settlement seal body built by the witness SDK."),
      request_binding: z.record(z.unknown()).optional().describe("SDK-generated binding; preserve unchanged on recovery."),
      settlement_tx: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional().describe("Known transaction for recovering an uncertain settlement."),
      ...PAY,
    },
    toBody: (a) => clean({ seal_body: a.seal_body, request_binding: a.request_binding, settlement_tx: a.settlement_tx }),
  },
  {
    name: "seal_ml_dsa",
    route: "/api/x402/sign",
    priceUsd: "$0.02",
    title: "Post-quantum signature (ML-DSA-65 / Dilithium-3)",
    description:
      "Get a post-quantum ML-DSA-65 / Dilithium-3 (NIST FIPS 204) signature over any message or hash — " +
      "signed locally, verifiable OFFLINE, with a verifiable on-chain-anchored receipt. Call when your " +
      "agent needs a durable, quantum-safe signature or proof of authenticity. Price $0.02 USDC on Base.",
    inputSchema: {
      message: z.string().optional().describe("UTF-8 message; we sign sha256(message)."),
      hash: z.string().optional().describe("Hex digest already computed; signed directly. Provide message OR hash."),
      ...PAY,
    },
    toBody: (a) => clean({ message: a.message, hash: a.hash }),
  },
  {
    name: "notarize_decision",
    route: "/api/x402/attest-decision",
    priceUsd: "$0.05",
    title: "Notarize an AI decision (auditable, on-chain)",
    description:
      "Notarize an AI decision: bind (input, output, model) into a post-quantum-signed, Black-Box-chained, " +
      "on-chain-anchored attestation with a re-verifiable permalink. Call to make an autonomous agent's " +
      "decision auditable and non-repudiable (EU AI Act Art. 12 alignment). Proves the decision was sealed " +
      "intact — NOT that it was correct. Price $0.05 USDC on Base.",
    inputSchema: {
      agent_id: z.string().describe("REQUIRED. Agent id (a 0x FRC-55 id is resolved on-chain; any label is bound as-is)."),
      input: z.string().describe("The context/input that produced the decision."),
      output: z.string().describe("The decision/output to seal."),
      model: z.string().optional().describe("Model/agent version that produced the decision (bound as model_id)."),
      ...PAY,
    },
    toBody: (a) => clean({ agent_id: a.agent_id, input: a.input, output: a.output, model_id: a.model }),
  },
  {
    name: "prove_provenance",
    route: "/api/x402/seal",
    priceUsd: "$0.05",
    title: "Post-quantum provenance seal (dataset/content)",
    description:
      "Seal the provenance of a dataset / training run / AI-generated content: a post-quantum signature + a " +
      "drand lower-bound timestamp (cannot be backdated) + an on-chain anchor. Call to prove PRIOR EXISTENCE " +
      "and INTEGRITY of AI data your agent produced or consumed. Privacy-preserving (send a hash). " +
      "Price $0.05 USDC on Base.",
    inputSchema: {
      content: z.string().optional().describe("Raw content to seal; we seal sha256(content)."),
      content_hash: z.string().optional().describe("A sha256 hex you already computed; sealed as-is (content never leaves you). Provide content OR content_hash."),
      kind: z.string().optional().describe('Provenance kind: "dataset" | "training" | "content".'),
      issuer: z.string().optional().describe("Optional declaring party (recorded)."),
      ...PAY,
    },
    toBody: (a) => clean({ content: a.content, content_hash: a.content_hash, kind: a.kind, issuer: a.issuer }),
  },
  {
    name: "attest_training",
    route: "/api/x402/attest-training",
    priceUsd: "$0.05",
    title: "AI training-provenance attestation (C2PA)",
    description:
      "Attest how/what an AI model was trained: a post-quantum-signed C2PA-style provenance manifest over a " +
      "dataset/training hash for a given model_id. Call to give a model a verifiable training-provenance " +
      "record. Privacy-preserving (send dataset_hash). Price $0.05 USDC on Base.",
    inputSchema: {
      model_id: z.string().describe('Model/dataset identifier (e.g. "fane-1", "acme-corpus-v3").'),
      dataset: z.string().optional().describe("Raw dataset/training content; we bind sha256(dataset)."),
      dataset_hash: z.string().optional().describe("A sha256 hex you already computed; bound as-is. Provide dataset OR dataset_hash."),
      issuer: z.string().optional().describe("Optional declaring party (recorded)."),
      content_type: z.string().optional().describe('Optional label (e.g. "application/jsonl", "dataset").'),
      ...PAY,
    },
    toBody: (a) => clean({ model_id: a.model_id, dataset: a.dataset, dataset_hash: a.dataset_hash, issuer: a.issuer, content_type: a.content_type }),
  },
  {
    name: "seal_cbom",
    route: "/api/x402/seal-cbom",
    priceUsd: "$0.05",
    title: "Seal a Cryptographic Bill of Materials (CBOM)",
    description:
      "Seal a CycloneDX CBOM (ECMA-424, cryptographic inventory) with a post-quantum signature + drand " +
      "timestamp — a machine-readable PQC-readiness / crypto-posture disclosure (CNSA 2.0, procurement). " +
      "Call to certify your declared cryptographic inventory. Price $0.05 USDC on Base.",
    inputSchema: {
      cbom: z.record(z.any()).describe("The CycloneDX CBOM (ECMA-424) as a JSON object."),
      issuer: z.string().optional().describe("Optional organization declaring the inventory (recorded)."),
      subject: z.string().optional().describe("Optional target system/product this CBOM describes (recorded)."),
      ...PAY,
    },
    toBody: (a) => clean({ cbom: a.cbom, issuer: a.issuer, subject: a.subject }),
  },
  {
    name: "verify_agent_kya",
    route: "/api/x402/verify-agent",
    priceUsd: "$0.03",
    title: "Know-Your-Agent: verify an agent credential",
    description:
      "Know-Your-Agent (KYA): verify another agent's FractalAI credential (post-quantum signature) and read " +
      "its live FRC-55 on-chain reputation. Call BEFORE trusting, delegating to, or paying another agent. " +
      "Returns a post-quantum-signed verdict. Price $0.03 USDC on Base.",
    inputSchema: {
      credential: z
        .record(z.any())
        .describe("A FractalAI KYA credential ({ claim, signature, public_key, credential_id }) to verify."),
      check_reputation: z.boolean().optional().describe("Default true: re-read live FRC-55 on-chain reputation."),
      ...PAY,
    },
    toBody: (a) => clean({ credential: a.credential, check_reputation: a.check_reputation }),
  },
  {
    name: "verify_proof",
    route: "/api/x402/verify-proof",
    priceUsd: "$0.01",
    title: "Verify a post-quantum signature (floor primitive)",
    description:
      "Verify a post-quantum signature over a message against a public key — auto-detects ML-DSA-65 / " +
      "Dilithium-3 (verified offline) or Dilithium-2 (node). The floor primitive ($0.01) for any proof " +
      "pipeline; returns a post-quantum-signed verdict receipt. Price $0.01 USDC on Base.",
    inputSchema: {
      signature: z.string().describe("Base64 signature to verify (ML-DSA-65 3309B or Dilithium-2 2420B)."),
      public_key: z.string().describe("Base64 public key to verify against (1952B ML-DSA-65 or 1312B Dilithium-2)."),
      message: z.string().optional().describe("The UTF-8 message that was signed. Provide message OR message_b64."),
      message_b64: z.string().optional().describe("The exact base64 bytes that were signed (use for /sign outputs)."),
      ...PAY,
    },
    toBody: (a) => clean({ signature: a.signature, public_key: a.public_key, message: a.message, message_b64: a.message_b64 }),
  },
];

/** Map a route short-name (the segment after /api/x402/) → its semantic MCP tool name. Single source. */
export const MCP_TOOL_FOR_ROUTE: Record<string, string> = Object.fromEntries(
  TOOLS.map((t) => [t.route.split("/api/x402/")[1], t.name]),
);

/** Discovery is informational; obtain a fresh challenge before authorizing payment. */
export function buildProofCatalog(resources: unknown, origin = baseUrl()) {
  if (!Array.isArray(resources)) throw new Error("Invalid discovery resources");
  return resources.map((r) => {
    const a = r.accepts?.[0] ?? {};
    const atomic = Number(a.amount ?? a.maxAmountRequired);
    const baseUsdc = ["base", "eip155:8453"].includes(a.network)
      && String(a.asset).toLowerCase() === "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    const url = new URL(String(r.resource));
    const sameOrigin = url.origin === new URL(origin).origin;
    const route = url.pathname.startsWith("/api/x402/") ? url.pathname.slice("/api/x402/".length) : "";
    const tool = sameOrigin && !url.search && !url.hash && r.method === "POST" && Object.hasOwn(MCP_TOOL_FOR_ROUTE, route)
      ? MCP_TOOL_FOR_ROUTE[route] ?? null : null;
    return {
      resource: r.resource,
      price_usdc: baseUsdc && Number.isSafeInteger(atomic) && atomic >= 0 ? atomic / 1e6 : null,
      asset: baseUsdc ? "USDC on Base" : a.asset ?? null,
      method: r.method,
      description: r.extensions?.bazaar?.description ?? null,
      payment_requirements: r.accepts ?? [],
      mcp_tool: tool,
      integration: tool ? "mcp" : "http",
      next_action: tool ? `Call ${tool} without payment for current requirements.`
        : "Use the advertised HTTP endpoint and schema; this installed MCP version has no tool for it.",
      input_schema: r.extensions?.bazaar?.inputSchema ?? null,
    };
  });
}

interface McpLike {
  registerTool: (
    name: string,
    def: { title: string; description: string; inputSchema: Record<string, z.ZodTypeAny> },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    handler: (args: Args, extra: any) => Promise<any>,
  ) => void;
}

/** Max serialized request body forwarded to a route (blunt a pre-402 free-work amplification). */
const MAX_BODY_BYTES = 256 * 1024;
/** Fetch timeout so a hung route never leaves the tool pending (aligned with the route's window). */
const FETCH_TIMEOUT_MS = 30_000;
const textErr = (o: unknown) => ({ isError: true as const, content: [{ type: "text" as const, text: JSON.stringify(o, null, 2) }] });

/**
 * Resolve the base64 X-PAYMENT to forward. The CANONICAL x402-MCP client (@x402/mcp) attaches the
 * payment as an OBJECT PaymentPayload in `_meta["x402/payment"]` — so we JSON+base64 it (which is
 * exactly `decodeExactEvmPayment`'s expected `base64(JSON(...))`). A string is forwarded verbatim
 * (already-encoded); the explicit `payment` arg is the universal manual fallback.
 */
function resolvePayment(metaPayment: unknown, argPayment: unknown): string | undefined {
  if (metaPayment && typeof metaPayment === "object") return Buffer.from(JSON.stringify(metaPayment)).toString("base64");
  if (typeof metaPayment === "string" && metaPayment) return metaPayment;
  if (typeof argPayment === "string" && argPayment) return argPayment;
  return undefined;
}

/** Register supported x402 routes as auto-payable MCP tools. Returns the tool names. */
export function registerX402Tools(server: McpLike): string[] {
  for (const t of TOOLS) {
    server.registerTool(t.name, { title: t.title, description: t.description, inputSchema: t.inputSchema }, async (args, extra) => {
      try {
        const bodyStr = JSON.stringify(t.toBody(args));
        const bodyBytes = Buffer.byteLength(bodyStr, "utf8");
        if (bodyBytes > MAX_BODY_BYTES) {
          return textErr({ error: "input too large", max_bytes: MAX_BODY_BYTES, got_bytes: bodyBytes });
        }
        const payment = resolvePayment(extra?._meta?.["x402/payment"], args.payment);
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (payment) {
          // v2 canonical header first; X-PAYMENT kept for v1 compatibility during the cut-over
          // (our routes read PAYMENT-SIGNATURE → X-PAYMENT via readPaymentHeader, so either is honored).
          headers["PAYMENT-SIGNATURE"] = payment;
          headers["X-PAYMENT"] = payment;
        }

        const res = await fetch(`${baseUrl()}${t.route}`, {
          method: "POST",
          headers,
          body: bodyStr,
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        const json: any = await res.json().catch(() => ({}));

        if (res.status === 402) {
          // The CANONICAL x402-MCP client reads PaymentRequired from `structuredContent` (preferred)
          // or `content[0].text` as JSON, then validates it against @x402/core's version union schema.
          // v2 requires the FULL body — x402Version:2, top-level `resource`, `accepts`, `extensions` —
          // so we surface the route's 402 body VERBATIM (truncating to {x402Version,accepts} would drop
          // `resource` and fail PaymentRequiredV2Schema, silently killing auto-pay). The body already IS
          // the canonical shape (built by buildChallenge402); we only guard that it's an object.
          const paymentRequired =
            json && typeof json === "object" ? json : { x402Version: 2, accepts: [] };
          return {
            isError: true as const,
            structuredContent: paymentRequired,
            content: [{ type: "text" as const, text: JSON.stringify(paymentRequired) }],
            _meta: { "x402/payment-required": paymentRequired }, // cosmetic; canonical clients read the above
          };
        }
        if (!res.ok) {
          // Generic error — do NOT relay the route's internal `detail` (avoid leaking internals).
          return textErr({ error: `x402 route error`, route: t.route, status: res.status });
        }
        return {
          content: [{ type: "text" as const, text: JSON.stringify(json, null, 2) }],
          _meta: { "x402/payment-response": json.payment ?? null },
        };
      } catch (e) {
        return textErr({ error: e instanceof Error ? e.message : String(e) });
      }
    });
  }
  return TOOLS.map((t) => t.name);
}
