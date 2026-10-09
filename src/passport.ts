/**
 * passport.ts — honest client for the live FractalAI endpoints that back the
 * agent-passport MCP server. Nothing here is stubbed:
 *
 *   - FRC-55 agent reads hit the real L1 JSON-RPC node (https://api.fractalai.net.co):
 *       fractal_getAgent / fractal_listAgents / fractal_getAgentStats.
 *   - Attestation records are fetched from the public /api/attestation/{hash} endpoint.
 *   - Dilithium-2 signatures are verified server-assisted via /api/proofmind/verify.
 *   - ML-DSA-65 (FIPS 204) signatures are verified 100% offline with the audited
 *     @noble/post-quantum library against the published /api/x402/receipt-key — no
 *     trust in the FractalAI server for that check (mirrors enterprise-trial/verify-receipt.mjs).
 *   - issue_passport seals an assertion through the REAL x402 (HTTP 402) attest-decision
 *     flow: with no payment it returns the payment challenge, it never fabricates a receipt.
 *
 * Honesty (project Regla 4): a passing signature proves the exact canonical bytes were signed
 * by the named key and that the record is internally consistent + anchored on FractalAI's L1.
 * It says NOTHING about the truthfulness or correctness of the signed content.
 */
import crypto from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

const DEFAULT_BASE_URL = "https://fractalai.net.co";
const DEFAULT_RPC_URL = "https://api.fractalai.net.co";
const DEFAULT_TIMEOUT_MS = 30_000;

export function baseUrl(): string {
  return (process.env.FRACTALAI_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
}
export function rpcUrl(): string {
  return (process.env.FRACTALAI_RPC_URL || DEFAULT_RPC_URL).replace(/\/+$/, "");
}

export class PassportError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public body?: unknown,
  ) {
    super(message);
    this.name = "PassportError";
  }
}

// ── low-level HTTP ───────────────────────────────────────────────────────────
async function httpJson(
  url: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<{ status: number; json: any }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), init.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": "agent-passport-mcp/0.1.0",
        ...(init.headers || {}),
      },
    });
    let json: any = null;
    const text = await res.text();
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = { raw: text };
      }
    }
    return { status: res.status, json };
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new PassportError(`Request to ${url} timed out`, 408);
    }
    throw new PassportError(
      `Network error calling ${url}: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    clearTimeout(timeout);
  }
}

// ── crypto helpers (identical byte-for-byte to verify-receipt.mjs) ───────────
export const sha256 = (s: string): string =>
  crypto.createHash("sha256").update(s, "utf8").digest("hex");

// ── PINNED trust anchor (out-of-band) ────────────────────────────────────────
/**
 * The FractalAI x402 ML-DSA-65 (NIST FIPS 204) receipt-signing PUBLIC KEY, pinned
 * IN SOURCE as an out-of-band trust anchor. Fetched 2026-08-09 from
 * https://fractalai.net.co/api/x402/receipt-key (algorithm "ml-dsa-65", 1952-byte key).
 *
 *   sha256(base64 pubkey string) = 7cf9d6316ba6c628184cbc822a95b6da4a2faa06bf7fb09ca0e10e7d85ebd835
 *   sha256(raw 1952-byte pubkey) = 7f59c29e48c486d9851d5185425f8832a7f907b4f5c68f0519656fe2c3514edf
 *
 * SECURITY (the whole point of this file): every INDEPENDENT ML-DSA-65 signature
 * verification MUST use THIS key. The verifier must NEVER verify against the
 * `public_key` embedded in the receipt/attestation, and must NEVER fetch the key it
 * verifies with from a configurable server endpoint — a malicious server can serve a
 * forged receipt together with a receipt-key equal to the attacker's own public key,
 * making "attacker == attacker" pass. Pinning the key here removes that channel.
 */
export const PINNED_ML_DSA65_ALGORITHM = "ml-dsa-65" as const;
export const PINNED_ML_DSA65_PUBKEY_SHA256 =
  "7cf9d6316ba6c628184cbc822a95b6da4a2faa06bf7fb09ca0e10e7d85ebd835" as const;
export const PINNED_ML_DSA65_PUBKEY =
  "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" as const;

/**
 * Key rotation (epoch 2, 2026-09-27): FractalAI publishes an append-only, ML-DSA-65-signed key directory
 * (/.well-known/x402-receipt-keys). Epoch 2 adds a second receipt key; epoch-1 receipts stay valid through the
 * overlap window. Every independent verification accepts a signature from ANY of these pinned keys — and
 * still NEVER a key quoted by the receipt or fetched from the server.
 *
 *   epoch 2: sha256(base64 pubkey string) = 86c139c960bb274cd2dc7b33a9f95fc1924371cded5214cd7c72a3db3edd59f9
 *            sha256(raw 1952-byte pubkey) = fb353a83bdfb97376606ef19086f1018e1a874eb1dd2c7686154ec8a4a91139b
 */
export const PINNED_ML_DSA65_PUBKEY_EPOCH2 =
  "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" as const;
export const PINNED_ML_DSA65_PUBKEY_EPOCH2_SHA256 =
  "86c139c960bb274cd2dc7b33a9f95fc1924371cded5214cd7c72a3db3edd59f9" as const;


/**
 * The EFFECTIVE pinned key used for every independent ML-DSA-65 verification. Defaults to
 * the embedded constant above. An OPERATOR may rotate it out-of-band via
 * FRACTALAI_PINNED_RECEIPT_KEY (a founder/deployer act — e.g. key rotation). It is NEVER
 * read from a receipt, an attestation, or any /api/x402/receipt-key response — that is the
 * exact untrusted channel this hardening closes.
 */
export function pinnedMlDsa65Pubkey(): string {
  const override = process.env.FRACTALAI_PINNED_RECEIPT_KEY;
  return (override && override.trim().length > 0 ? override.trim() : PINNED_ML_DSA65_PUBKEY);
}

/**
 * ALL pinned keys an independent verification may accept (epoch 1 + epoch 2), deduplicated. The env
 * override FRACTALAI_PINNED_RECEIPT_KEY may hold one key or several comma-separated keys; when set it
 * REPLACES the embedded pins (an operator act). Never sourced from a receipt or a server response.
 */
export function pinnedMlDsa65Pubkeys(): string[] {
  const override = process.env.FRACTALAI_PINNED_RECEIPT_KEY;
  const fromEnv = override ? override.split(",").map((k) => k.trim()).filter((k) => k.length > 0) : [];
  const keys = fromEnv.length > 0 ? fromEnv : [PINNED_ML_DSA65_PUBKEY, PINNED_ML_DSA65_PUBKEY_EPOCH2];
  return Array.from(new Set(keys));
}

/** The FRC-55 agent id form the node RPC expects: a 0x-prefixed 32-byte hash. */
export function isFrc55Id(s: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(s.trim());
}

/** Extract an attestation hash (0x…) from a permalink or a raw hash. */
export function extractHash(arg: string): string {
  const m = arg.match(/0x[0-9a-fA-F]{16,}/);
  if (!m) {
    throw new PassportError(
      "Could not find an attestation hash (0x…) in the input. Pass a permalink like " +
        "https://fractalai.net.co/attestation/0x… or the bare 0x hash.",
    );
  }
  return m[0];
}

export interface AttestationDecision {
  agent_id: string;
  input: string;
  output: string;
  input_sha256: string;
  output_sha256: string;
  model_id: string;
  model_version: string;
  timestamp: number | string;
}
export interface AttestationRecord {
  attestation_hash: string;
  algorithm: string;
  standard?: string;
  anchored?: { chain?: string; block_number?: number | null };
  decision: AttestationDecision;
  signature: string;
  public_key: string;
}

/**
 * Coerce a decision timestamp to an integer, REJECTING anything that is not a whole number.
 * The signer (frontend `canonicalMessage`) puts an integer unix-seconds value in the signed
 * bytes; a non-integer (float, NaN, "abc", null, "") means the served record cannot possibly
 * reconstruct the signed message — we throw instead of silently coercing garbage to NaN/null,
 * which would produce attacker-controllable canonical bytes.
 */
export function canonicalTimestamp(t: number | string | null | undefined): number {
  if (typeof t === "number") {
    if (!Number.isInteger(t)) throw new PassportError(`Non-integer decision.timestamp: ${t}`);
    return t;
  }
  if (typeof t === "string" && /^-?\d+$/.test(t.trim())) return Number(t.trim());
  throw new PassportError(`Invalid/non-integer decision.timestamp: ${JSON.stringify(t)}`);
}

/**
 * Reconstruct the exact canonical message that was signed — identical field order and
 * types to enterprise-trial/verify-receipt.mjs and frontend `canonicalMessage()` so an
 * independent party gets byte-identical bytes. Hardened: the timestamp MUST be an integer
 * (canonicalTimestamp throws otherwise), and model_id/model_version are carried through as
 * the strings the signer used (never coerced) so the bytes stay reproducible.
 */
export function reconstructCanonical(d: AttestationDecision): string {
  return JSON.stringify({
    agent_id: d.agent_id,
    input_hash: sha256(d.input),
    output_hash: sha256(d.output),
    model_id: d.model_id,
    model_version: d.model_version,
    timestamp: canonicalTimestamp(d.timestamp),
  });
}

// ── FractalAI L1 JSON-RPC (FRC-55 agent registry reads) ──────────────────────
export async function rpcCall<T = any>(method: string, params: unknown[] = []): Promise<T> {
  const { status, json } = await httpJson(rpcUrl(), {
    method: "POST",
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (status !== 200) {
    throw new PassportError(`RPC ${method} returned HTTP ${status}`, status, json);
  }
  if (json?.error) {
    throw new PassportError(
      `RPC ${method} error: ${json.error?.message || JSON.stringify(json.error)}`,
      undefined,
      json.error,
    );
  }
  return json?.result as T;
}

export function getAgent(agentId: string): Promise<any> {
  return rpcCall("fractal_getAgent", [agentId]);
}
export function listAgents(): Promise<{ agents: any[]; count: number }> {
  return rpcCall("fractal_listAgents", []);
}
export function getAgentStats(): Promise<any> {
  return rpcCall("fractal_getAgentStats", []);
}

// ── attestation record + keys ────────────────────────────────────────────────
export async function fetchAttestation(hash: string): Promise<AttestationRecord> {
  const { status, json } = await httpJson(`${baseUrl()}/api/attestation/${hash}`);
  if (status === 404) {
    throw new PassportError(`Attestation ${hash} not found`, 404, json);
  }
  if (status !== 200) {
    throw new PassportError(`Fetching attestation ${hash} failed (HTTP ${status})`, status, json);
  }
  return json as AttestationRecord;
}

/**
 * Fetch the server-advertised receipt key. INFORMATIONAL ONLY — this value is served by the
 * (configurable, possibly malicious) FractalAI base URL, so it is NEVER used to verify a
 * signature. It is only compared against the PINNED key for a transparency/telemetry check
 * ("does the live server still advertise the key we pinned?"). Never fail-open on it.
 */
export async function fetchReceiptKey(): Promise<{ algorithm?: string; public_key?: string } | null> {
  try {
    const { status, json } = await httpJson(`${baseUrl()}/api/x402/receipt-key`);
    return status === 200 ? json : null;
  } catch {
    return null;
  }
}

/** Server-assisted Dilithium-2 (round-3) verification over the exact signed bytes. */
export async function verifyProofServer(params: {
  signed_message_b64: string;
  signature: string;
  public_key: string;
}): Promise<boolean | null> {
  const { status, json } = await httpJson(`${baseUrl()}/api/proofmind/verify`, {
    method: "POST",
    body: JSON.stringify(params),
  });
  if (status !== 200) return null;
  return json?.valid === true;
}

/**
 * 100%-offline ML-DSA-65 (FIPS 204) verification. Never throws — false on any bad input.
 * SECURITY: callers MUST pass the PINNED key (pinnedMlDsa65Pubkey()) as `pkB64`, never a key
 * taken from the receipt/attestation. Verifying against a receipt-supplied key is exactly the
 * forgery the red-team exploited (attacker signs with their key + supplies their key ⇒ pass).
 */
export function verifyMlDsa65(canonical: string, sigB64: string, pkB64: string): boolean {
  try {
    return ml_dsa65.verify(
      Uint8Array.from(Buffer.from(sigB64, "base64")),
      new TextEncoder().encode(canonical),
      Uint8Array.from(Buffer.from(pkB64, "base64")),
    );
  } catch {
    return false;
  }
}

// ── x402 attest-decision (real HTTP 402 flow used by issue_passport) ─────────
function txHashPaymentHeader(txHash: string, from?: string): string {
  const payload: Record<string, string> = { txHash };
  if (from) payload.from = from;
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

export interface AttestSealResult {
  paid: boolean;
  /** When paid=false: the raw 402 challenge (accepts[]) so the caller knows how to pay. */
  paymentRequired?: unknown;
  /** When paid=true: the sealed receipt the server returned after settling payment. */
  result?: any;
  status: number;
}

/**
 * Seal an assertion via the real /api/x402/attest-decision resource. With a confirmed
 * USDC-on-Base txHash we retry with the X-PAYMENT header (facilitator-less mode) and the
 * server settles + returns the receipt. Without payment we return the 402 challenge — we
 * never fabricate a receipt.
 */
export async function sealAttestDecision(
  body: Record<string, unknown>,
  payment?: { txHash?: string; from?: string },
): Promise<AttestSealResult> {
  const headers: Record<string, string> = {};
  if (payment?.txHash) {
    headers["X-PAYMENT"] = txHashPaymentHeader(payment.txHash, payment.from);
  }
  const { status, json } = await httpJson(`${baseUrl()}/api/x402/attest-decision`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    timeoutMs: 45_000,
  });
  if (status === 200) return { paid: true, result: json, status };
  if (status === 402) return { paid: false, paymentRequired: json, status };
  throw new PassportError(
    `x402 attest-decision returned ${status}: ${json?.error || "unexpected error"}`,
    status,
    json,
  );
}

/** Best-effort extraction of the attestation hash / permalink from a sealed receipt. */
export function permalinkFromReceipt(receipt: any): { hash?: string; permalink?: string } {
  const hash =
    receipt?.attestation_hash ||
    receipt?.hash ||
    receipt?.attestation?.attestation_hash ||
    receipt?.verifiable_receipt?.attestation_hash ||
    receipt?.anchored?.attestation_hash;
  if (!hash) return {};
  return { hash, permalink: `${baseUrl()}/attestation/${hash}` };
}
