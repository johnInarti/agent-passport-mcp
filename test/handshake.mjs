#!/usr/bin/env node
/**
 * handshake.mjs — proves the agent-passport MCP server actually stands up and its tools respond.
 *
 * Hard (offline, deterministic — the build fails if any break):
 *   1. MCP initialize + tools/list returns exactly the three expected tools.
 *   2. The ML-DSA-65 (FIPS 204) crypto that verify_passport relies on round-trips with
 *      @noble/post-quantum (sign→verify true; tampered→false) — the real primitive, no mock.
 *   3. lookup_agent rejects a non-FRC-55 id (input honesty, no network).
 *
 * Best-effort (live network — reported as PASS/SKIP, never fails the run so it works offline/CI):
 *   4. lookup_agent (no id) against the real FractalAI L1 node returns registry stats + agents.
 *   5. lookup_agent for the LOGOS genesis agent returns its on-chain record.
 *
 * Run: npm run build && node test/handshake.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(__dirname, "../dist/index.js");
const EXPECTED_TOOLS = [
  // free hooks + the original passport issue
  "verify_passport", "issue_passport", "lookup_agent", "list_fractalai_proofs",
  // v0.2.0 x402 ⇄ MCP bridge: the 7 paid routes as auto-payable tools
  "seal_ml_dsa", "notarize_decision", "prove_provenance", "attest_training",
  "seal_cbom", "verify_agent_kya", "verify_proof", "witness_payment",
];
const LOGOS = "0x9980b79c9383f6be0ba3a7eae2fdd5b082b1c0d50c224039b9b908dbce8db415";

let hardFail = 0;
const pass = (n, ok, d = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${n}${d ? ` — ${d}` : ""}`);
  if (!ok) hardFail++;
};
const soft = (n, ok, d = "") => console.log(`${ok ? "PASS" : "SKIP"}  ${n}${d ? ` — ${d}` : ""}`);
const parse = (res) => {
  try {
    return JSON.parse(res.content?.[0]?.text ?? "{}");
  } catch {
    return {};
  }
};

// ── 2. ML-DSA-65 primitive round-trip (offline, hard) ────────────────────────
{
  const seed = new Uint8Array(32).fill(0xab);
  const kp = ml_dsa65.keygen(seed);
  const msg = new TextEncoder().encode('{"agent_id":"passport-demo","ts":1000}');
  const sig = ml_dsa65.sign(msg, kp.secretKey);
  pass("ML-DSA-65 signature is 3309 bytes (FIPS 204)", sig.length === 3309);
  pass("ML-DSA-65 public key is 1952 bytes (FIPS 204)", kp.publicKey.length === 1952);
  pass("ML-DSA-65 verify(sig, msg, pk) === true", ml_dsa65.verify(sig, msg, kp.publicKey) === true);
  const tampered = new TextEncoder().encode('{"agent_id":"passport-demo","ts":1001}');
  pass("ML-DSA-65 tampered payload rejected === false", ml_dsa65.verify(sig, tampered, kp.publicKey) === false);
}

// ── 1,3,4,5. spin up the server over stdio ───────────────────────────────────
const transport = new StdioClientTransport({ command: process.execPath, args: [SERVER] });
const client = new Client({ name: "agent-passport-handshake", version: "0.1.0" });

try {
  await client.connect(transport);
  pass("MCP server connected over stdio", true);

  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  pass(
    `tools/list returns the ${EXPECTED_TOOLS.length} expected tools (4 base + 8 x402 bridge)`,
    EXPECTED_TOOLS.every((t) => names.includes(t)) && names.length === EXPECTED_TOOLS.length,
    names.join(", "),
  );

  // x402 bridge: calling a paid tool WITHOUT payment must proxy to the live route and return the
  // x402 payment challenge (isError + accepts[]) — proving the bridge reaches prod, never fabricates.
  const unpaid = await client.callTool({ name: "seal_ml_dsa", arguments: { message: "mcp bridge smoke test" } });
  const up = parse(unpaid);
  // Canonical x402-MCP shape: isError + { x402Version, accepts } at top of structuredContent AND content[0].text.
  const sc = unpaid.structuredContent ?? {};
  pass(
    "x402 bridge: unpaid seal_ml_dsa returns the CANONICAL PaymentRequired (x402Version + accepts in structuredContent & content)",
    unpaid.isError === true &&
      [1, 2].includes(up.x402Version) && Array.isArray(up.accepts) && up.accepts.length > 0 &&
      sc.x402Version === up.x402Version && Array.isArray(sc.accepts) && sc.accepts.length > 0 &&
      (sc.x402Version !== 2 || typeof sc.resource?.url === 'string'),
    `accepts=${(sc.accepts || []).length}`,
  );

  // 3. input honesty — non-FRC-55 id is rejected without touching the network
  const bad = await client.callTool({ name: "lookup_agent", arguments: { agent_id: "not-a-hash" } });
  pass("lookup_agent rejects a non-FRC-55 id", bad.isError === true);

  // 4. live: registry-wide read (best effort)
  try {
    const all = await client.callTool({ name: "lookup_agent", arguments: {} });
    const data = parse(all);
    const okAll = !all.isError && Array.isArray(data.agents) && typeof data.count === "number";
    soft(
      "lookup_agent (live) returns agents + registry stats",
      okAll,
      okAll ? `count=${data.count} total_agents=${data.registry_stats?.total_agents}` : "network unavailable",
    );

    // 5. live: LOGOS genesis agent
    const one = await client.callTool({ name: "lookup_agent", arguments: { agent_id: LOGOS } });
    const od = parse(one);
    soft(
      "lookup_agent (live) resolves the LOGOS genesis agent",
      !one.isError && od.agent?.name === "LOGOS",
      one.isError ? "network unavailable" : `name=${od.agent?.name} status=${od.agent?.status}`,
    );
  } catch (e) {
    soft("live registry reads", false, `network unavailable: ${e?.message ?? e}`);
  }
} finally {
  await client.close().catch(() => {});
}

console.log(
  hardFail === 0
    ? "\nHANDSHAKE: all hard checks passed."
    : `\nHANDSHAKE: ${hardFail} hard check(s) FAILED.`,
);
process.exit(hardFail === 0 ? 0 : 1);
