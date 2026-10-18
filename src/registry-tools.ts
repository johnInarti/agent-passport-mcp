/**
 * registry-tools — Fractal Agent Commons (B.2): `list_agents`, `get_agent_manifest`,
 * `verify_agent_manifest` over MCP, with OFFLINE verification.
 *
 * Trust model (honest, two levels):
 *   - The signed index (/.well-known/agents.json) is verified against the ML-DSA-65 notary key
 *     PINNED IN SOURCE (`pinnedMlDsa65Pubkeys()` — the same pins the receipt verifier uses). That
 *     verdict is INDEPENDENT of the server: `index_signature_verified`. An index whose signature
 *     does not verify is an ERROR with no `agents` at all (never "a list with a flag"); a verified
 *     index must also be FRESH: `expires_at` in the future, and neither `issued_at` nor `seq` below
 *     the last index this process accepted for the same base URL (anti-rollback, in-memory).
 *   - A manifest is signed by the AGENT's own key, which cannot be pinned here (agents come and go).
 *     The manifest's embedded key is used for verification ONLY when it equals the key the registry /
 *     node reports as the agent's CURRENT key (fetched from …/passport — i.e. registry-assisted), or
 *     when the caller supplies the key out-of-band (`pubkey_b64url` — caller-trusted). A manifest is
 *     NEVER verified against its own embedded key alone: that is the "attacker == attacker" forgery.
 *
 * Canon: JCS (sorted keys, no whitespace) identical to the frontend's x402-witness-canon `jcs`;
 * manifest_id = sha256hex(JCS(manifest without `signature` and `manifest_id`));
 * signature over utf8("fractalai-agent-manifest/1\n" + manifest_id).
 */
import { z } from "zod";
import { createHash } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { baseUrl, pinnedMlDsa65Pubkeys } from "./passport.js";

export const MANIFEST_SCHEMA = "fractalai-agent-manifest/1";
export const MANIFEST_SIGN_PREFIX = "fractalai-agent-manifest/1\n";
export const INDEX_SCHEMA = "fractalai-agents-index/1";
export const INDEX_SIGN_PREFIX = "fractalai-agents-index/1\n";
export const ML_DSA_65_PUBKEY_BYTES = 1952;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;
/**
 * Agent-declared locators are PINNED to the official origins (registry review #11, 2026-10-12): the
 * registry refuses anything else with 422, and this offline verifier flags them too, so a validly
 * signed manifest handed to you directly can never point you at a look-alike jwks/rpc/verify host.
 */
export const PINNED_LOCATORS = {
  receipts_directory: "https://fractalai.net.co/.well-known/x402-receipt-keys",
  jwks: "https://fractalai.net.co/.well-known/jwks.json",
  http: "https://fractalai.net.co",
  rpc: "https://api.fractalai.net.co",
  verify: ["/api/passport/verify", "https://fractalai.net.co/api/passport/verify"],
} as const;

/** Offending locator paths (empty = all pinned). */
export function unpinnedLocators(m: unknown): string[] {
  const rec = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
  const keys = rec(rec(m).keys), endpoints = rec(rec(m).endpoints);
  const out: string[] = [];
  if (keys.receipts_directory !== PINNED_LOCATORS.receipts_directory) out.push("keys.receipts_directory");
  if (keys.jwks !== PINNED_LOCATORS.jwks) out.push("keys.jwks");
  if (endpoints.http !== PINNED_LOCATORS.http) out.push("endpoints.http");
  if (endpoints.rpc !== PINNED_LOCATORS.rpc) out.push("endpoints.rpc");
  if (!(PINNED_LOCATORS.verify as readonly unknown[]).includes(endpoints.verify)) out.push("endpoints.verify");
  return out;
}
/** Max tolerance for an index `issued_at` ahead of this clock (seconds). */
export const INDEX_MAX_SKEW_SEC = 300;

const MAX_DEPTH = 24;
const MAX_NODES = 10_000;

/** RFC 8785-style canonical JSON — byte-identical to the canonicalizer the FractalAI server signs with. */
export function jcs(v: unknown, depth = 0, counter: { n: number } = { n: 0 }): string {
  if (++counter.n > MAX_NODES) throw new Error(`jcs: too many nodes (>${MAX_NODES})`);
  if (depth > MAX_DEPTH) throw new Error(`jcs: nesting depth exceeds ${MAX_DEPTH}`);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("jcs: non-finite number");
    return JSON.stringify(v);
  }
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map((x) => jcs(x, depth + 1, counter)).join(",") + "]";
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    return "{" + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ":" + jcs(obj[k], depth + 1, counter)).join(",") + "}";
  }
  throw new Error(`jcs: unsupported ${typeof v}`);
}

export const sha256Hex = (data: string | Uint8Array): string =>
  createHash("sha256").update(typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data)).digest("hex");

export const b64url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Strict base64url decode: alphabet-checked and canonical (re-encoding must reproduce the input). */
export function b64urlDecodeStrict(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || s.length === 0 || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const out = Uint8Array.from(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
  return b64url(out) === s ? out : null;
}

export const kidOf = (pub: Uint8Array): string => sha256Hex(pub).slice(0, 16);

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => !!v && typeof v === "object" && !Array.isArray(v);

export function manifestId(m: Rec): string {
  const { signature: _s, manifest_id: _i, ...rest } = m;
  void _s; void _i;
  return sha256Hex(jcs(rest));
}

export interface OfflineCheck { name: string; pass: boolean; detail?: string }

/**
 * Offline manifest verification against a CALLER-SUPPLIED public key (base64url). Fail-closed; every
 * step is an explicit check. `alg` is anchored: "ML-DSA-44"/"none"/anything else fails before crypto.
 */
export function verifyManifestOffline(manifest: unknown, pubB64url: string): { ok: boolean; checks: OfflineCheck[]; manifest_id?: string; kid?: string } {
  const checks: OfflineCheck[] = [];
  const push = (name: string, pass: boolean, detail?: string) => { checks.push({ name, pass, ...(detail ? { detail } : {}) }); return pass; };
  if (!isRec(manifest)) { push("manifest is a JSON object", false); return { ok: false, checks }; }
  const m = manifest;
  if (!push("schema == fractalai-agent-manifest/1", m.schema === MANIFEST_SCHEMA)) return { ok: false, checks };
  const sig = isRec(m.signature) ? m.signature : null;
  const keys = isRec(m.keys) && isRec(m.keys.signing) ? (m.keys.signing as Rec) : null;
  if (!push("signature.alg == ML-DSA-65 (anchored, never inferred)", sig?.alg === "ML-DSA-65")) return { ok: false, checks };
  if (!push("keys.signing.alg == ML-DSA-65", keys?.alg === "ML-DSA-65")) return { ok: false, checks };
  const pub = b64urlDecodeStrict(pubB64url);
  if (!push("verifier public key is 1952 bytes (ML-DSA-65)", !!pub && pub.length === ML_DSA_65_PUBKEY_BYTES)) return { ok: false, checks };
  const kid = kidOf(pub as Uint8Array);
  push("keys.signing.pub equals the verifier key", keys?.pub === pubB64url);
  push("keys.signing.kid == sha256(pub)[0:16]", keys?.kid === kid);
  if (!push("signature.kid == sha256(verifier key)[0:16]", sig?.kid === kid)) return { ok: false, checks, kid };
  const sigBytes = b64urlDecodeStrict(sig?.sig);
  if (!push("signature.sig is a canonical base64url 3309-byte signature", !!sigBytes && sigBytes.length === ML_DSA_65_SIGNATURE_BYTES)) return { ok: false, checks, kid };
  let id = "";
  try { id = manifestId(m); } catch (e) { push("canonicalisation (JCS)", false, String(e)); return { ok: false, checks, kid }; }
  if (!push("manifest_id == sha256(JCS(manifest without signature/manifest_id))", m.manifest_id === id)) return { ok: false, checks, kid, manifest_id: id };
  let verified = false;
  try {
    verified = ml_dsa65.verify(sigBytes as Uint8Array, new TextEncoder().encode(MANIFEST_SIGN_PREFIX + id), pub as Uint8Array) === true;
  } catch { verified = false; }
  push("ML-DSA-65 signature verifies OFFLINE over \"fractalai-agent-manifest/1\\n\" + manifest_id", verified);
  const unpinned = unpinnedLocators(m);
  push("keys.jwks/receipts_directory and endpoints.http/rpc/verify are the official FractalAI locators (#11)", unpinned.length === 0, unpinned.length ? `not pinned: ${unpinned.join(", ")}` : undefined);
  const issued = typeof m.issued_at === "number" ? m.issued_at : NaN;
  const expires = typeof m.expires_at === "number" ? m.expires_at : NaN;
  push("lifetime <= 30 days and expires_at > issued_at", Number.isFinite(issued) && Number.isFinite(expires) && expires > issued && expires - issued <= 30 * 86400);
  push("not expired (now)", Number.isFinite(expires) && expires > Math.floor(Date.now() / 1000));
  return { ok: checks.every((c) => c.pass), checks, manifest_id: id, kid };
}

/** The scope a verifier EXPECTS: `null` for the global index, `{ region }` for `?region=XX`. */
export type IndexScope = { region: string } | null;

/**
 * Offline verification of the signed agents index against the PINNED notary keys (std base64 list).
 * R5-4: `expectedScope` is MANDATORY (`null` = the GLOBAL index was asked, `{ region }` = that regional
 * index was asked) and the signed `scope` must match it (checkIndexScope) — an authentic regional index
 * is otherwise a valid signature for a verifier that ignores `scope` (omission attack: the CO subset
 * served as "global"). `reason` is exactly "index_scope_mismatch" (with `detail`) in that case; a JS
 * caller that omits the argument fails closed.
 */
export function verifyIndexOffline(index: unknown, pinnedStdB64: string[], expectedScope: IndexScope): { ok: boolean; reason?: string; detail?: string; signer_kid?: string } {
  if (expectedScope === undefined) return { ok: false, reason: "expected_scope_required (null for the global index, { region } for a regional one)" };
  if (expectedScope !== null && (!isRec(expectedScope) || Object.keys(expectedScope).length !== 1 || typeof expectedScope.region !== "string" || !REGION_RE.test(expectedScope.region))) return { ok: false, reason: "expected_scope_invalid" };
  if (!isRec(index) || index.schema !== INDEX_SCHEMA) return { ok: false, reason: "schema is not fractalai-agents-index/1" };
  const sig = isRec(index.signature) ? index.signature : null;
  if (!sig || sig.alg !== "ML-DSA-65") return { ok: false, reason: "signature.alg is not ML-DSA-65" };
  const sigBytes = b64urlDecodeStrict(sig.sig);
  if (!sigBytes || sigBytes.length !== ML_DSA_65_SIGNATURE_BYTES) return { ok: false, reason: "bad signature size" };
  const { signature: _s, ...rest } = index;
  void _s;
  const msg = new TextEncoder().encode(INDEX_SIGN_PREFIX + sha256Hex(jcs(rest)));
  for (const k of pinnedStdB64) {
    let pub: Uint8Array;
    try { pub = Uint8Array.from(Buffer.from(k, "base64")); } catch { continue; }
    if (pub.length !== ML_DSA_65_PUBKEY_BYTES) continue;
    const kid = kidOf(pub);
    if (sig.kid !== kid) continue; // the index names its signer; only that pin is tried
    let verified = false;
    try { verified = ml_dsa65.verify(sigBytes, msg, pub) === true; } catch { verified = false; }
    if (!verified) return { ok: false, reason: "signature invalid under the pinned key with this kid", signer_kid: kid };
    // scope is INSIDE the signed canon: compared only once the signature verified, so a mismatch
    // always means "authentic index, but not the one that was asked for".
    const sc = checkIndexScope(index, expectedScope === null ? undefined : expectedScope.region);
    if (!sc.ok) return { ok: false, reason: sc.reason, detail: sc.detail, signer_kid: kid };
    return { ok: true, signer_kid: kid };
  }
  return { ok: false, reason: "signature.kid matches none of the pinned notary keys", signer_kid: typeof sig.kid === "string" ? sig.kid : undefined };
}

export type IndexFreshness =
  | { ok: true; issued_at: number; expires_at: number; seq: number }
  | { ok: false; reason: "index_malformed" | "index_expired" | "index_issued_in_future" | "index_rollback"; detail: string };

/**
 * Freshness + anti-rollback of a signature-verified index: `issued_at`, `expires_at` and `seq` must be
 * non-negative integers, expires_at > issued_at, expires_at > now, issued_at <= now + skew, and
 * neither issued_at nor seq may be below the last index accepted (`lastSeen`).
 */
export function checkIndexFreshness(index: Rec, now: number, lastSeen: { issued_at: number; seq: number } | null): IndexFreshness {
  const n = (v: unknown) => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null);
  const issued_at = n(index.issued_at), expires_at = n(index.expires_at), seq = n(index.seq);
  if (issued_at === null || expires_at === null || seq === null || expires_at <= issued_at) {
    return { ok: false, reason: "index_malformed", detail: "issued_at, expires_at and seq must be non-negative integers with expires_at > issued_at" };
  }
  if (expires_at <= now) return { ok: false, reason: "index_expired", detail: `expires_at ${expires_at} <= now ${now}` };
  if (issued_at > now + INDEX_MAX_SKEW_SEC) return { ok: false, reason: "index_issued_in_future", detail: `issued_at ${issued_at} > now ${now} + ${INDEX_MAX_SKEW_SEC}` };
  if (lastSeen && (issued_at < lastSeen.issued_at || seq < lastSeen.seq)) {
    return { ok: false, reason: "index_rollback", detail: `issued_at/seq ${issued_at}/${seq} below the last accepted index ${lastSeen.issued_at}/${lastSeen.seq}` };
  }
  return { ok: true, issued_at, expires_at, seq };
}

/**
 * Last accepted index per base URL AND scope — process memory (a restart forgets; the expiry window
 * still holds). Keyed per scope because the server memoises each index separately: a regional index
 * built later than the global one is not a rollback of it (and vice-versa).
 */
const lastSeenIndex = new Map<string, { issued_at: number; seq: number }>();
export function resetIndexFreshnessState(): void { lastSeenIndex.clear(); }

export const REGION_RE = /^[A-Z]{2}$/;
export type IndexScopeCheck = { ok: true; scope: { region: string } | null } | { ok: false; reason: "index_scope_mismatch"; detail: string };
/**
 * The signed `scope` must match what was asked (2026-10-12): a regional request needs
 * `scope.region === region` (exactly that key, exactly that code); a global request needs scope
 * absent (pre-scope indexes) or null. A global index re-served for a regional request — or a
 * regional one for a global request — is a mismatch, never a fallback. `scope` is INSIDE the signed
 * canon, so this is checked AFTER the signature verified (a forged scope fails the signature first).
 */
export function checkIndexScope(index: Rec, region: string | undefined): IndexScopeCheck {
  const scope = index.scope;
  if (region !== undefined) {
    if (!isRec(scope) || Object.keys(scope).length !== 1 || scope.region !== region) {
      return { ok: false, reason: "index_scope_mismatch", detail: `asked for region ${region}, the signed index carries scope ${JSON.stringify(scope ?? null)}` };
    }
    return { ok: true, scope: { region } };
  }
  if (scope !== undefined && scope !== null) {
    return { ok: false, reason: "index_scope_mismatch", detail: `asked for the GLOBAL index, the signed index carries scope ${JSON.stringify(scope)}` };
  }
  return { ok: true, scope: null };
}

// ── registry HTTP (data is UNTRUSTED until verified) ─────────────────────────
async function getJson(url: string): Promise<{ status: number; json: any }> {
  const res = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
  return { status: res.status, json };
}

export const isFrc55 = (s: unknown): s is string => typeof s === "string" && /^0x[0-9a-fA-F]{64}$/.test(s);

/**
 * The agent's CURRENT key as the registry/node reports it (registry-assisted trust). `passport_valid`
 * is the registry's `valid`, which (review 3, R3-2) already folds in its LOCAL checks: pinned root
 * signature, Merkle inclusion, the node-signed agent_binding when served, AND continuity of the served
 * identity (canonical_key) with the binding the registry holds for this agent_id — so a hostile RPC
 * serving another identity's genuine passport for this agent reads valid:false here, never "current".
 * `passport_reasons` relays the registry's reasons (e.g. passport_binding_mismatch) when not valid.
 */
export async function fetchCurrentKey(agentId: string): Promise<{ pub_b64url: string; kid: string; alg: string | null; key_allowed: boolean; bound: boolean; agent_status: string; passport_valid: boolean; passport_reasons: string[] | null } | null> {
  const { status, json } = await getJson(`${baseUrl()}/api/agents/registry/${agentId.toLowerCase()}/passport`);
  if (status !== 200 || !json?.current_key?.pub) return null;
  let reasons = Array.isArray(json.reasons) ? json.reasons.filter((r: unknown): r is string => typeof r === "string").slice(0, 16) : null;
  const alg = typeof json.current_key.alg === "string" ? json.current_key.alg : null;
  // Only ML-DSA-65 (2026-10-12): decided HERE too, never from the registry's word alone — a served key
  // whose alg tag is not ml-dsa-65 or whose bytes are not 1952 is never "current" for this client.
  const pubBytes = b64urlDecodeStrict(json.current_key.pub);
  const algTag = alg ? alg.toLowerCase().replace(/[_-]/g, "") : null;
  const key_allowed = algTag === "mldsa65" && !!pubBytes && pubBytes.length === ML_DSA_65_PUBKEY_BYTES;
  if (!key_allowed && !(reasons ?? []).includes("key_algorithm_not_allowed")) reasons = [...(reasons ?? []), "key_algorithm_not_allowed"];
  // R4-1: "current" needs an identity the REGISTRY binds to this agent_id — a published row
  // (registered) or a continuity verdict over its binding. An unregistered id whose /passport merely
  // relays what some channel served (registered:false, continuity.ok:null) is never current here,
  // whatever `valid` says; a pre-R4 registry without these fields reads as unbound (fail-closed).
  const bound = json.registered === true || json.continuity?.ok === true;
  if (!bound && !(reasons ?? []).includes("binding_unverified") && !(reasons ?? []).includes("not_registered")) reasons = [...(reasons ?? []), "not_registered"];
  return { pub_b64url: String(json.current_key.pub), kid: String(json.current_key.kid), alg, key_allowed, bound, agent_status: String(json.agent_status), passport_valid: json.valid === true && key_allowed && bound, passport_reasons: reasons };
}

interface McpLike {
  registerTool: (name: string, def: { title: string; description: string; inputSchema: Record<string, z.ZodTypeAny> }, handler: (args: any) => Promise<any>) => unknown;
}
const text = (data: unknown, isError = false) => ({ ...(isError ? { isError: true } : {}), content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] });

export function registerRegistryTools(server: McpLike): string[] {
  server.registerTool(
    "list_agents",
    {
      title: "List FractalAI Agent Commons agents (signed index)",
      description:
        "Free. Fetch /.well-known/agents.json — the ML-DSA-65-SIGNED index of agents whose latest fractalai-agent-manifest/1 " +
        "is CURRENT (key equals the agent's current key on the FractalAI node, passport verifies, FRC-55 status Active, not expired) " +
        "— and verify the index signature OFFLINE against the notary key PINNED in this package (never a key the server hands over). " +
        "An index whose signature does not verify, that is expired (expires_at), or that is OLDER (issued_at/seq) than one already " +
        "accepted in this process is returned as an ERROR with no agents. " +
        "Returns { index_signature_verified: true, signer_kid, issued_at, expires_at, seq, scope, registry { identity_root, height }, agents[] { id, name, did, manifest_url, " +
        "manifest_id, version, kid, status } }. Set include_all to also list non-current agents (rotated key, paused, expired) " +
        "from /api/agents/registry?status=all with their reasons. Set region (ISO 3166-1 alpha-2, e.g. CO) to fetch the SEPARATELY " +
        "signed regional index (?region=CO: only current agents whose manifest declares that country); the signed scope.region MUST " +
        "equal the request — a global index re-served for a regional request is an ERROR index_scope_mismatch, never a fallback; a " +
        "valid region with no agents is a signed empty list; an unlisted code is the server's 400 region_invalid. " +
        "Prices are never listed: the binding price is each resource's live 402.",
      inputSchema: {
        include_all: z.boolean().optional().describe("Also return non-current agents with the reasons they are not current."),
        region: z.string().regex(REGION_RE).optional().describe("ISO 3166-1 alpha-2 (uppercase). Fetches the regional index and requires scope.region to match."),
      },
    },
    async ({ include_all, region }) => {
      try {
        const base = baseUrl();
        const scopeKey = `${base}#${region ?? ""}`;
        const { status, json } = await getJson(`${base}/.well-known/agents.json${region ? `?region=${encodeURIComponent(region)}` : ""}`);
        if (status === 400 && json?.error === "region_invalid") return text({ error: "region_invalid", region, detail: json.detail ?? null }, true);
        if (status !== 200) return text({ error: `agents index HTTP ${status}`, detail: json }, true);
        // R5-4: the expected scope is part of the verification itself (null = global, { region } = regional).
        const expectedScope: IndexScope = region ? { region } : null;
        const v = verifyIndexOffline(json, pinnedMlDsa65Pubkeys(), expectedScope);
        if (!v.ok) {
          // scope is inside the signed canon: a mismatch is an AUTHENTIC index for another scope (never a fallback).
          if (v.reason === "index_scope_mismatch") {
            return text({ error: "index_scope_mismatch", index_signature_verified: true, signer_kid: v.signer_kid ?? null, detail: v.detail ?? null, requested_region: region ?? null, signed_scope: json?.scope ?? null }, true);
          }
          // No agents on a failed signature: an unverified list is not data, it is an attack surface.
          return text({ error: "index_signature_invalid", index_signature_verified: false, signer_kid: v.signer_kid ?? null, detail: v.reason, issued_at: json?.issued_at ?? null }, true);
        }
        const fresh = checkIndexFreshness(json, Math.floor(Date.now() / 1000), lastSeenIndex.get(scopeKey) ?? null);
        if (!fresh.ok) {
          return text({ error: fresh.reason, index_signature_verified: true, signer_kid: v.signer_kid ?? null, detail: fresh.detail, issued_at: json?.issued_at ?? null, expires_at: json?.expires_at ?? null, seq: json?.seq ?? null }, true);
        }
        lastSeenIndex.set(scopeKey, { issued_at: fresh.issued_at, seq: fresh.seq });
        const out: Rec = {
          index_signature_verified: true,
          signer_kid: v.signer_kid ?? null,
          issued_at: fresh.issued_at,
          expires_at: fresh.expires_at,
          seq: fresh.seq,
          scope: expectedScope,
          registry: json.registry,
          count: Array.isArray(json.agents) ? json.agents.length : 0,
          agents: Array.isArray(json.agents) ? json.agents : [],
          meaning: "index_signature_verified=true means the FractalAI notary (pinned key) signed exactly this list (scope included), it is not expired and not older than one already seen for this scope; it does not vouch for what any agent does.",
        };
        if (include_all) {
          const all = await getJson(`${baseUrl()}/api/agents/registry?status=all${region ? `&region=${encodeURIComponent(region)}` : ""}`);
          out.all_agents = all.status === 200 ? all.json?.agents ?? [] : { error: `HTTP ${all.status}` };
        }
        return text(out);
      } catch (e) {
        return text({ error: e instanceof Error ? e.message : String(e) }, true);
      }
    },
  );

  server.registerTool(
    "get_agent_manifest",
    {
      title: "Fetch an agent's signed manifest (current or a specific version)",
      description:
        "Free. Fetch /api/agents/registry/<id> (current manifest) or /api/agents/registry/<id>/v/<n> (immutable version), then verify it " +
        "OFFLINE: manifest_id recomputed with JCS, ML-DSA-65 signature checked — against the manifest's embedded key ONLY if that key " +
        "equals the agent's CURRENT key reported by the registry/node (…/passport), otherwise reported as key_not_current/rotated. " +
        "Returns { manifest, ok, verdict (current|not_current), signature_ok, passport_valid, agent_active, registry_verification " +
        "(key_status, agent_status, passport_valid), offline { ok, checks[] }, trust }. ok = signature_ok && passport_valid && " +
        "agent_active; anything else is an error with not_ok_because[] (a Destroyed agent is never ok).",
      inputSchema: {
        agent_id: z.string().describe("FRC-55 agent id (0x + 64 hex)."),
        version: z.number().int().min(1).optional().describe("Specific version (immutable). Omit for the current manifest."),
      },
    },
    async ({ agent_id, version }) => {
      try {
        if (!isFrc55(agent_id)) return text({ error: "agent_id must be 0x + 64 hex (FRC-55)" }, true);
        const id = agent_id.toLowerCase();
        const url = version ? `${baseUrl()}/api/agents/registry/${id}/v/${version}` : `${baseUrl()}/api/agents/registry/${id}`;
        const { status, json } = await getJson(url);
        if (status !== 200) return text({ error: `registry HTTP ${status}`, detail: json }, true);
        const manifest = json?.manifest;
        const current = await fetchCurrentKey(id);
        const embedded = manifest?.keys?.signing?.pub;
        let offline: ReturnType<typeof verifyManifestOffline> | { ok: false; checks: OfflineCheck[] };
        let trust: string;
        if (current && current.key_allowed && typeof embedded === "string" && embedded === current.pub_b64url) {
          offline = verifyManifestOffline(manifest, current.pub_b64url);
          trust = "registry-assisted: the verification key is the agent's CURRENT key as reported by the registry/node, and it equals the manifest's embedded key";
        } else {
          const why = !current ? "current key unavailable from the registry"
            : !current.key_allowed ? `key_algorithm_not_allowed: the node serves a ${current.alg ?? "unknown-alg"} key; only ML-DSA-65 is admitted (nothing verified under it)`
            : "key_not_current: manifest key differs from the current key (rotated or forged)";
          offline = { ok: false, checks: [{ name: "manifest key equals the agent's current ML-DSA-65 key (registry/node)", pass: false, detail: why }] };
          trust = "not verified: the manifest's embedded key is NEVER used alone";
        }
        // Same verdict shape as verify_agent_manifest (review 2, R2-7b): `ok` is true ONLY when the
        // signature verifies offline AND the passport is valid AND the agent is Active. A Destroyed
        // agent or an invalid passport is an ERROR with explicit reasons — never "offline.ok: true"
        // standing alone as if it meant "this agent is fine".
        const signature_ok = offline.ok;
        const passport_valid = current ? current.passport_valid === true : null;
        const agent_active = current ? current.agent_status === "Active" : null;
        const ok = signature_ok && passport_valid === true && agent_active === true;
        const not_ok_because = ok ? undefined : [
          ...(signature_ok ? [] : ["signature_ok=false"]),
          ...(passport_valid === true ? [] : [passport_valid === null ? "passport_valid=null (registry/node unavailable)" : "passport_valid=false (node verdict + registry local checks)"]),
          ...(agent_active === true ? [] : [agent_active === null ? "agent_active=null (registry/node unavailable)" : `agent_active=false (status ${current?.agent_status})`]),
        ];
        return text({
          agent_id: id, version: manifest?.version ?? null, manifest_id: manifest?.manifest_id ?? null, manifest,
          ok, verdict: ok ? "current" : "not_current", signature_ok, passport_valid, agent_active, agent_status: current?.agent_status ?? null,
          ...(not_ok_because ? { not_ok_because } : {}),
          ...(current?.passport_reasons?.length ? { passport_reasons: current.passport_reasons } : {}),
          registry_verification: json?.verification ?? null,
          offline, trust,
          scope: "ok=true means: the agent's CURRENT registered ML-DSA-65 key signed THIS exact description, its passport verifies and the agent is Active on the FractalAI L1. It does not prove the agent performs well.",
        }, !ok);
      } catch (e) {
        return text({ error: e instanceof Error ? e.message : String(e) }, true);
      }
    },
  );

  server.registerTool(
    "verify_agent_manifest",
    {
      title: "Verify a fractalai-agent-manifest/1 offline",
      description:
        "Free. Verify a manifest JSON you were handed: JCS manifest_id recomputation + ML-DSA-65 signature (alg anchored; key 1952 B, " +
        "signature 3309 B; nothing inferred from sizes) + lifetime. The verification key is (a) pubkey_b64url if you supply it " +
        "(caller-trusted, fully offline), else (b) the agent's CURRENT key as the registry/node reports it, used only if it equals the " +
        "manifest's embedded key (registry-assisted). The embedded key alone is never trusted. Returns three SEPARATE verdicts " +
        "{ signature_ok, passport_valid, agent_active } and ok = all three true with verdict \"current\"/\"not_current\" (with a " +
        "caller-supplied key the registry is not consulted: verdict is \"signature_only\", ok is null when the signature verifies " +
        "(never true) and false when it does not, passport_valid and agent_active are null — say so to the user). Plus { checks[], trust }.",
      inputSchema: {
        manifest: z.record(z.any()).describe("The manifest JSON object (fractalai-agent-manifest/1)."),
        pubkey_b64url: z.string().optional().describe("Optional: the agent's ML-DSA-65 public key (base64url, 1952 bytes) from a source YOU trust."),
      },
    },
    async ({ manifest, pubkey_b64url }) => {
      try {
        if (pubkey_b64url) {
          // Caller-supplied key: a SIGNATURE-ONLY verdict (review 2, R2-7a). `ok` is NEVER true on this
          // path — null when the signature (and the #11 locator pins) verify, so a client reading `ok`
          // cannot mistake "the signature verifies under the key you gave me" for the registry-assisted
          // "current" verdict (passport + on-chain status) — and false when the offline check FAILS
          // (broken signature, foreign locator): a proven negative is reported as a negative, never as
          // "unknown" (#11 ∩ R2-7a harmonised, fail-closed).
          const r = verifyManifestOffline(manifest, pubkey_b64url);
          return text({
            ...r, ok: r.ok ? null : false, verdict: "signature_only", signature_ok: r.ok, passport_valid: null, agent_active: null,
            trust: "caller-supplied key (fully offline): signature only — passport and on-chain status NOT checked; verdict is never `current` on this path",
          }, !r.ok);
        }
        const id = manifest?.agent?.id;
        if (!isFrc55(id)) return text({ ok: false, error: "manifest.agent.id must be an FRC-55 id; or pass pubkey_b64url" }, true);
        const current = await fetchCurrentKey(String(id));
        if (!current) return text({ ok: false, error: "current key unavailable from the registry/node; pass pubkey_b64url to verify fully offline" }, true);
        const embedded = manifest?.keys?.signing?.pub;
        if (embedded !== current.pub_b64url || !current.key_allowed) {
          return text({
            ok: false, verdict: "not_current", error: current.key_allowed ? "key_not_current" : "key_algorithm_not_allowed",
            detail: current.key_allowed
              ? "manifest.keys.signing.pub is not the agent's current key on the node (rotated or forged); its signature is NOT checked against the embedded key"
              : `the node serves a signing key that is not ML-DSA-65 (alg ${current.alg ?? "unknown"}); only ML-DSA-65 is admitted — nothing is verified under it`,
            current_kid: current.kid, current_alg: current.alg, agent_status: current.agent_status,
            ...(current.passport_reasons?.length ? { passport_reasons: current.passport_reasons } : {}),
          }, true);
        }
        const r = verifyManifestOffline(manifest, current.pub_b64url);
        const signature_ok = r.ok;
        const passport_valid = current.passport_valid === true;
        const agent_active = current.agent_status === "Active";
        const ok = signature_ok && passport_valid && agent_active;
        return text({
          ...r, ok, verdict: ok ? "current" : "not_current", signature_ok, passport_valid, agent_active, agent_status: current.agent_status,
          ...(ok ? {} : { not_ok_because: [...(signature_ok ? [] : ["signature_ok=false"]), ...(passport_valid ? [] : ["passport_valid=false (node verdict)"]), ...(agent_active ? [] : [`agent_active=false (status ${current.agent_status})`])] }),
          ...(current.passport_reasons?.length ? { passport_reasons: current.passport_reasons } : {}),
          trust: "registry-assisted: embedded key == current key reported by the registry/node",
        }, !ok);
      } catch (e) {
        return text({ ok: false, error: e instanceof Error ? e.message : String(e) }, true);
      }
    },
  );

  return ["list_agents", "get_agent_manifest", "verify_agent_manifest"];
}
