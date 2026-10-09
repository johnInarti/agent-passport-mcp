#!/usr/bin/env node
/**
 * agent-passport MCP server.
 *
 * The free tool a developer uses in 5 lines to ISSUE and independently VERIFY a verifiable
 * passport for an AI agent, over the Model Context Protocol — so any MCP client (Claude
 * Desktop, LangChain, CrewAI, AutoGen, OpenAI Agents) can call it.
 *
 * Tools:
 *   - verify_passport  (free)  Independently verify an agent passport / attestation:
 *                              ML-DSA-65 (FIPS 204) signature offline + Dilithium-2
 *                              server-assisted + FRC-55 on-chain agent state.
 *   - issue_passport   (x402)  Bind an agent id + a signed assertion into a re-verifiable
 *                              credential via the real x402 attest-decision flow.
 *   - lookup_agent     (free)  Public FRC-55 registry read: an agent's on-chain state,
 *                              rating and call count, plus registry-wide stats.
 *
 * HONESTY (project Regla 4): these tools do real things against real endpoints — the live
 * FractalAI L1 JSON-RPC node and the public web endpoints — and never fake a result. A valid
 * passport proves an IDENTITY + a specific ATTESTED assertion are cryptographically intact and
 * anchored on FractalAI's L1. It does NOT prove the assertion is true, nor that the agent's
 * decision was correct, and it is NOT a decentralized reputation registration. See each tool's
 * description and the README "Honest scope" section.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createHash } from "node:crypto";
import {
  baseUrl,
  rpcUrl,
  PassportError,
  extractHash,
  fetchAttestation,
  reconstructCanonical,
  sha256,
  verifyProofServer,
  verifyMlDsa65,
  pinnedMlDsa65Pubkeys,
  PINNED_ML_DSA65_PUBKEY_SHA256,
  isFrc55Id,
  getAgent,
  listAgents,
  getAgentStats,
  sealAttestDecision,
  permalinkFromReceipt,
} from "./passport.js";
import { registerX402Tools, buildProofCatalog } from "./x402-tools.js";

const server = new McpServer({ name: "agent-passport", version: "0.2.5" });

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}
function fail(message: string, extra?: unknown) {
  return {
    isError: true,
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({ error: message, ...(extra ? { detail: extra } : {}) }, null, 2),
      },
    ],
  };
}
function errBody(e: unknown) {
  return e instanceof PassportError ? e.body : undefined;
}
function errMsg(e: unknown) {
  return e instanceof PassportError ? e.message : String(e);
}

interface Check {
  name: string;
  trust: "independent" | "server-assisted";
  pass: boolean;
  detail?: string;
}

// ── verify_passport (free) ───────────────────────────────────────────────────
server.registerTool(
  "verify_passport",
  {
    title: "Independently verify an agent passport",
    description:
      "Free. Independently verify a verifiable agent passport / attestation. Give it an attestation " +
      "permalink (https://fractalai.net.co/attestation/0x…) or the bare 0x hash — optionally plus the " +
      "receipt JSON you were handed at issue time (if it carries an `ml_dsa65` field). It: (1) fetches " +
      "the public attestation record, (2) [independent] recomputes sha256(input)/sha256(output) and " +
      "reconstructs the exact canonical signed message, (3) [independent] verifies the ML-DSA-65 (NIST " +
      "FIPS 204) signature 100% OFFLINE with @noble/post-quantum against a key PINNED IN SOURCE (the " +
      "FractalAI receipt key — NEVER the key quoted in the receipt), (4) [server-assisted] verifies the " +
      "Dilithium-2 signature over the canonical bytes plus a tamper negative-control, and (5) reads the " +
      "agent's on-chain FRC-55 state (fractal_getAgent) when agent_id is an on-chain id. Returns " +
      "{ valid_independent, valid_server_assisted, valid, algorithm, checks[], anchored, decision, agent }. " +
      "TRUST: rely on `valid_independent` — it is true ONLY when an ML-DSA-65 signature verifies against the " +
      "pinned key (fail-closed: no/empty signature ⇒ false). `valid_server_assisted` trusts the FractalAI " +
      "server. `valid` aliases the conservative independent verdict. HONEST SCOPE: a pass means the signature " +
      "is intact over the exact bytes and the record is internally consistent and anchored on FractalAI's L1 " +
      "— it does NOT prove the assertion is true or that the agent's decision was correct.",
    inputSchema: {
      attestation: z
        .string()
        .describe("Attestation permalink (…/attestation/0x…) or the bare 0x attestation hash."),
      receipt: z
        .record(z.any())
        .optional()
        .describe(
          "Optional: the receipt JSON handed to you at issue time. If it contains an `ml_dsa65` " +
            "{ signature, public_key, signed_payload_sha256 } object, the ML-DSA-65 signature is " +
            "verified fully offline against the published receipt key.",
        ),
    },
  },
  async ({ attestation, receipt }) => {
    try {
      const hash = extractHash(attestation);
      const att = await fetchAttestation(hash);
      const d = att.decision;
      const checks: Check[] = [];

      // 2. [independent] content hashes
      checks.push({
        name: "sha256(input) matches published input_sha256",
        trust: "independent",
        pass: sha256(d.input) === d.input_sha256,
      });
      checks.push({
        name: "sha256(output) matches published output_sha256",
        trust: "independent",
        pass: sha256(d.output) === d.output_sha256,
      });

      // Reconstruct the exact canonical bytes. Hardened: a non-integer timestamp (or any
      // malformed field the signer could not have signed) FAILS an explicit [independent]
      // check instead of coercing garbage — fail-closed, not fail-open.
      let canonical: string | null = null;
      let canonicalB64: string | null = null;
      try {
        canonical = reconstructCanonical(d);
        canonicalB64 = Buffer.from(canonical, "utf8").toString("base64");
        checks.push({
          name: "canonical signed message is well-formed (integer timestamp, stable fields)",
          trust: "independent",
          pass: true,
        });
      } catch (e) {
        checks.push({
          name: "canonical signed message is well-formed (integer timestamp, stable fields)",
          trust: "independent",
          pass: false,
          detail: errMsg(e),
        });
      }

      // 3. [independent] ML-DSA-65 offline against the PINNED key. This is the LOAD-BEARING
      //    independent authenticity check and it is FAIL-CLOSED: if there is no ml_dsa65
      //    signature, or it is empty, or the canonical could not be built, this check FAILS
      //    explicitly (it never silently disappears). The verification key is ALWAYS the
      //    pinned trust anchor — NEVER ml.public_key from the receipt.
      // Key rotation (epoch 2): ANY pinned key may verify (epoch-1 receipts stay valid through the
      // overlap window). Still never the key quoted by the receipt, never a fetched key.
      const pinnedKeys = pinnedMlDsa65Pubkeys();
      const ml = (receipt as any)?.ml_dsa65 ?? null;
      let mlVerified = false;

      // Informational only: does the receipt's quoted key match a pin? (never used to verify)
      if (ml?.public_key) {
        const quotedIsPinned = pinnedKeys.includes(ml.public_key);
        checks.push({
          name: "receipt ml_dsa65.public_key equals a PINNED key (informational — not used to verify)",
          trust: "independent",
          pass: quotedIsPinned,
          detail:
            quotedIsPinned
              ? undefined
              : "receipt quotes a key that is NOT among the pinned trust anchors — ignored for verification",
        });
      }

      const mlSig = typeof ml?.signature === "string" ? ml.signature.trim() : "";
      if (canonical && mlSig.length > 0) {
        mlVerified = pinnedKeys.some((pinned) => verifyMlDsa65(canonical, mlSig, pinned)); // ALWAYS a pinned key
        checks.push({
          name: "ML-DSA-65 (FIPS 204) signature verifies against the PINNED receipt key — OFFLINE",
          trust: "independent",
          pass: mlVerified,
        });
        if (ml.signed_payload_sha256) {
          checks.push({
            name: "ml_dsa65.signed_payload_sha256 matches reconstructed canonical",
            trust: "independent",
            pass: ml.signed_payload_sha256 === sha256(canonical),
          });
        }
      } else {
        checks.push({
          name: "ML-DSA-65 (FIPS 204) signature verifies against the PINNED receipt key — OFFLINE",
          trust: "independent",
          pass: false,
          detail: !canonical
            ? "canonical could not be reconstructed — cannot verify independently"
            : !ml
              ? "no ml_dsa65 field in the receipt — pass the issue-time receipt JSON to verify independently"
              : "ml_dsa65.signature missing/empty — cannot verify independently (fail-closed)",
        });
      }

      // 4. [server-assisted] Dilithium-2 over canonical + tamper negative control. Only
      //    meaningful when the canonical bytes exist; otherwise fail-closed.
      if (canonical && canonicalB64) {
        const valid = await verifyProofServer({
          signed_message_b64: canonicalB64,
          signature: att.signature,
          public_key: att.public_key,
        });
        if (valid !== null) {
          checks.push({
            name: "Dilithium-2 signature verifies over canonical message",
            trust: "server-assisted",
            pass: valid === true,
          });
          const tampered = await verifyProofServer({
            signed_message_b64: Buffer.from(canonical + "X", "utf8").toString("base64"),
            signature: att.signature,
            public_key: att.public_key,
          });
          checks.push({
            name: "negative control: tampered payload is REJECTED",
            trust: "server-assisted",
            pass: tampered === false,
          });
        } else {
          checks.push({
            name: "Dilithium-2 server-assisted verify",
            trust: "server-assisted",
            pass: false,
            detail: "/api/proofmind/verify unavailable",
          });
        }
      } else {
        checks.push({
          name: "Dilithium-2 server-assisted verify",
          trust: "server-assisted",
          pass: false,
          detail: "canonical could not be reconstructed",
        });
      }

      // 5. on-chain FRC-55 agent state (only when agent_id is an on-chain id)
      let agent: any = null;
      let agentNote: string | undefined;
      if (isFrc55Id(d.agent_id)) {
        try {
          agent = await getAgent(d.agent_id);
        } catch (e) {
          agentNote = `on-chain lookup failed: ${errMsg(e)}`;
        }
      } else {
        agentNote =
          "decision.agent_id is a free-form label, not an FRC-55 on-chain id — no on-chain record queried";
      }

      // ── SPLIT TRUST VERDICTS ────────────────────────────────────────────────
      // valid_independent : verifiable WITHOUT trusting the server. Requires the pinned
      //   ML-DSA-65 signature to have actually verified AND every [independent] check to pass.
      //   No pinned signature ⇒ false (fail-closed). This is the ONLY field a consumer who
      //   does not trust the FractalAI server should rely on.
      // valid_server_assisted : the Dilithium-2 path, which trusts /api/proofmind/verify.
      const independentChecks = checks.filter((c) => c.trust === "independent");
      const serverChecks = checks.filter((c) => c.trust === "server-assisted");
      const valid_independent = mlVerified && independentChecks.every((c) => c.pass);
      const valid_server_assisted = serverChecks.length > 0 && serverChecks.every((c) => c.pass);

      return ok({
        // Back-compat alias, deliberately set to the CONSERVATIVE (independent) verdict so any
        // consumer still reading `valid` gets the safe, unforgeable answer — never a
        // server-assisted-only pass.
        valid: valid_independent,
        valid_independent,
        valid_server_assisted,
        algorithm: att.algorithm,
        attestation_hash: att.attestation_hash,
        anchored: att.anchored ?? null,
        decision: {
          agent_id: d.agent_id,
          model_id: d.model_id,
          model_version: d.model_version,
          timestamp: d.timestamp,
        },
        agent,
        agent_note: agentNote,
        checks,
        canonical,
        ml_dsa65_offline_verified: mlVerified,
        pinned_receipt_key_sha256: PINNED_ML_DSA65_PUBKEY_SHA256,
        pinned_receipt_keys_sha256: pinnedMlDsa65Pubkeys().map((k) => createHash("sha256").update(k).digest("hex")),
        scope:
          "valid_independent = an ML-DSA-65 (FIPS 204) signature over the exact canonical bytes " +
          "verifies against the PINNED FractalAI receipt key (no trust in the server) AND the record " +
          "is internally consistent. valid_server_assisted trusts /api/proofmind/verify. Neither is a " +
          "claim that the content is true or the decision correct. Rely on valid_independent if you do " +
          "not trust the server.",
      });
    } catch (e) {
      return fail(errMsg(e), errBody(e));
    }
  },
);

// ── issue_passport (x402) ────────────────────────────────────────────────────
server.registerTool(
  "issue_passport",
  {
    title: "Issue a verifiable agent passport",
    description:
      "Issue a verifiable agent passport = an agent id + a SIGNED assertion + a re-verifiable permalink. " +
      "It (a) resolves the agent on the FRC-55 registry when agent_id is an on-chain id (fractal_getAgent), " +
      "and (b) seals the assertion through the REAL x402 (HTTP 402) attest-decision flow: the assertion is " +
      "Dilithium-2 signed, Black-Box chained and anchored on FractalAI's L1, returning a receipt anyone can " +
      "re-check with verify_passport. WHAT IT PROVES: this exact assertion was attested by (and bound to) " +
      "this agent id, is cryptographically intact, and is anchored on-chain. WHAT IT DOES NOT PROVE: that " +
      "the assertion is TRUE, that the agent's decision was CORRECT, or any decentralized/consensus-scored " +
      "reputation — it does NOT register reputation. PAYMENT: this is a paid x402 resource ($0.05 USDC on " +
      "Base). Call once WITHOUT payment_tx_hash to get the exact payment challenge (accepts[]: amount, USDC " +
      "asset, payTo); pay that USDC yourself; then call again WITH payment_tx_hash set to the confirmed " +
      "transaction hash. Without payment it returns the challenge — it never fabricates a passport.",
    inputSchema: {
      agent_id: z
        .string()
        .describe(
          "The agent's identifier. A 0x FRC-55 on-chain id is resolved against the registry; any other " +
            "stable label is bound as-is (and flagged agent_resolved:false).",
        ),
      assertion: z
        .string()
        .describe("The action/claim to attest and bind to the agent (becomes the sealed decision output)."),
      input: z
        .string()
        .optional()
        .describe("Optional context/input that produced the assertion (defaults to the assertion itself)."),
      model: z.string().optional().describe("Optional model/agent version that produced the assertion."),
      payment_tx_hash: z
        .string()
        .regex(/^0x[0-9a-fA-F]{64}$/)
        .optional()
        .describe(
          "A confirmed USDC-on-Base transaction hash paying the required amount. If omitted, the tool " +
            "returns the x402 payment challenge instead of a passport. One txHash issues exactly one passport.",
        ),
      payer: z
        .string()
        .regex(/^0x[0-9a-fA-F]{40}$/)
        .optional()
        .describe("Optional payer address hint."),
    },
  },
  async ({ agent_id, assertion, input, model, payment_tx_hash, payer }) => {
    try {
      let agent: any = null;
      let agentResolved = false;
      let agentNote: string | undefined;
      if (isFrc55Id(agent_id)) {
        try {
          agent = await getAgent(agent_id);
          agentResolved = Boolean(agent && agent.agent_id);
        } catch (e) {
          agentNote = `on-chain lookup failed: ${errMsg(e)}`;
        }
      } else {
        agentNote = "agent_id is a free-form label, not an FRC-55 on-chain id — bound as-is, not resolved";
      }

      const body: Record<string, unknown> = { agent_id, input: input ?? assertion, output: assertion };
      if (model) body.model = model;

      const seal = await sealAttestDecision(body, { txHash: payment_tx_hash, from: payer });

      const scope = {
        proves: [
          "This exact assertion was attested and bound to this agent_id.",
          "The assertion is cryptographically intact (Dilithium-2 signed; ML-DSA-65 additive) and anchored on FractalAI's L1.",
        ],
        does_not_prove: [
          "That the assertion is true.",
          "That the agent's decision/action was correct.",
          "Any decentralized or consensus-scored reputation — this does NOT register reputation.",
        ],
      };

      if (!seal.paid) {
        return ok({
          issued: false,
          agent_resolved: agentResolved,
          agent,
          agent_note: agentNote,
          note:
            "Payment required. Pay the amount in paymentRequired.accepts (USDC on Base to payTo), then " +
            "call again with payment_tx_hash set to the confirmed transaction hash.",
          paymentRequired: seal.paymentRequired,
          scope,
        });
      }

      const link = permalinkFromReceipt(seal.result);
      return ok({
        issued: true,
        agent_resolved: agentResolved,
        agent,
        agent_note: agentNote,
        passport: {
          agent_id,
          assertion,
          attestation_hash: link.hash ?? null,
          permalink: link.permalink ?? null,
          receipt: seal.result,
          verify_with: "verify_passport (pass the permalink; include this receipt for the offline ML-DSA-65 check)",
        },
        scope,
      });
    } catch (e) {
      return fail(errMsg(e), errBody(e));
    }
  },
);

// ── lookup_agent (free) ──────────────────────────────────────────────────────
server.registerTool(
  "lookup_agent",
  {
    title: "Look up an agent's public on-chain state",
    description:
      "Free. Read an agent's PUBLIC state from the FRC-55 registry on the live FractalAI L1 node " +
      "(fractal_getAgent) — name, owner, status, model, price_per_call, total_calls, rating, total_ratings, " +
      "created_at — for reputation/status checks. Omit agent_id to list all registered agents " +
      "(fractal_listAgents). Always returns registry-wide stats (fractal_getAgentStats). This is on-chain " +
      "registry data as reported by the node; ratings are the registry's own counters, not an independent audit.",
    inputSchema: {
      agent_id: z
        .string()
        .optional()
        .describe("A 0x FRC-55 on-chain agent id to fetch. Omit to list all agents."),
    },
  },
  async ({ agent_id }) => {
    try {
      const stats = await getAgentStats().catch(() => null);
      if (agent_id) {
        if (!isFrc55Id(agent_id)) {
          return fail(
            "agent_id must be a 0x FRC-55 on-chain id (0x + 64 hex chars). Omit it to list all agents.",
          );
        }
        const agent = await getAgent(agent_id);
        return ok({ agent, registry_stats: stats });
      }
      const list = await listAgents();
      return ok({ agents: list.agents, count: list.count, registry_stats: stats });
    } catch (e) {
      return fail(errMsg(e), errBody(e));
    }
  },
);

// ── list_fractalai_proofs (free): self-describing discovery. Reads the canonical /.well-known/x402.json
//    live and returns the full proof catalog (name, price, algorithm, when-to-call) — so ONE call maps
//    our whole surface and it AUTO-HEALS any drift (it reflects the source of truth, not a hardcoded copy). ──
server.registerTool(
  "list_fractalai_proofs",
  {
    title: "Discover FractalAI's post-quantum proof catalog",
    description:
      "Free. Return the live catalog of FractalAI's x402 post-quantum proof services (price, algorithm, " +
      "endpoint, and what each proves) read straight from the canonical /.well-known/x402.json. Call this " +
      "first to discover every proof you can buy: signatures, AI-decision notarization, dataset/training " +
      "provenance, CBOM sealing, Know-Your-Agent, and signature verification.",
    inputSchema: {},
  },
  async () => {
    try {
      const res = await fetch(`${baseUrl()}/.well-known/x402.json`, { signal: AbortSignal.timeout(15_000) });
      if (!res.ok) return fail(`discovery manifest HTTP ${res.status}`);
      const wk: any = await res.json();
      const catalog = buildProofCatalog(wk.resources);
      return ok({
        provider: wk.provider?.name ?? "FractalAI Network",
        proof_signature: "served ML-DSA-65 / Dilithium-3 (NIST FIPS 204), offline-verifiable; on-chain anchor is Dilithium-2 (gated cut-over)",
        pay_with: "x402 — USDC on Base, gasless EIP-3009",
        count: catalog.length,
        catalog,
        onboarding: [
          "Select a resource. Use its MCP tool when available, otherwise its HTTP endpoint and schema.",
          "Request the current payment challenge without a payment authorization.",
          "Your wallet client must check network, token, recipient, amount and its spending limit before signing.",
          "Persist the exact request and authorization before submitting; use the witness SDK for request-bound purchases.",
          "Submit once. If the response is lost, recover the same request; do not authorize a replacement payment automatically.",
          "Verify the delivered proof using an independently trusted key. A discovery response is not a completed purchase.",
        ],
        note: "Automatic payment requires a compatible wallet client and an explicit spending policy; the MCP server holds no buyer wallet.",
      });
    } catch (e) {
      return fail(errMsg(e));
    }
  },
);

// ── x402 ⇄ MCP bridge: the 8 paid FractalAI x402 routes as auto-payable, semantically-named tools
//    (seal_ml_dsa, notarize_decision, prove_provenance, attest_training, seal_cbom, verify_agent_kya,
//    verify_proof). Standard _meta["x402/payment"] convention → any x402-wallet agent auto-pays. ──
const x402ToolNames = registerX402Tools(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(
    `agent-passport-mcp v0.2.5 connected (stdio). node=${rpcUrl()} web=${baseUrl()} | ` +
      `free: verify_passport, lookup_agent | x402-paid: issue_passport, ${x402ToolNames.join(", ")}\n`,
  );

  // ── Opt-out auto-demo: prove this isn't vaporware with ONE real, free call against the live
  //    node right after connecting — visible in stderr, fire-and-forget, never blocks or delays
  //    the MCP handshake above. Set AGENT_PASSPORT_AUTODEMO=0 to disable. ──
  if (process.env.AGENT_PASSPORT_AUTODEMO !== "0") {
    getAgentStats()
      .then((stats) => {
        process.stderr.write(
          `[agent-passport-mcp demo] real call to ${rpcUrl()} (fractal_getAgentStats) succeeded — ` +
            `${stats?.total_agents ?? "?"} agents registered on FRC-55 right now. This is live, not ` +
            `mocked. Try lookup_agent or list_fractalai_proofs next. ` +
            `(Set AGENT_PASSPORT_AUTODEMO=0 to skip this on next start.)\n`,
        );
      })
      .catch((e) => {
        process.stderr.write(
          `[agent-passport-mcp demo] startup call to the live node failed (${errMsg(e)}) — the MCP ` +
            `server itself is unaffected; this only checks connectivity to ${rpcUrl()}.\n`,
        );
      });
  }
}

main().catch((err) => {
  process.stderr.write(
    `agent-passport-mcp fatal: ${err instanceof Error ? err.stack : String(err)}\n`,
  );
  process.exit(1);
});
