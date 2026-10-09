#!/usr/bin/env node
/**
 * x402-mcp-e2e — the "prueba reina": proves the x402⇄MCP magnet works END-TO-END the way a real
 * wallet-enabled agent would use it.
 *
 * WITHOUT funds (runs now, deterministic):
 *   A. _META PLUMBING (the mechanism the whole auto-pay depends on): an in-memory MCP client passes
 *      _meta["x402/payment"] on a tools/call and the server handler receives it in extra._meta.
 *   B. DISCOVERY: list_fractalai_proofs returns the live catalog.
 *   C. CHALLENGE: an unpaid seal_ml_dsa returns the CANONICAL PaymentRequired ({x402Version, accepts}).
 *
 * WITH funds (set PAYER_PRIVATE_KEY = a Base wallet holding ~$0.05 USDC; no ETH needed — gasless):
 *   D. PRUEBA REINA: sign a real EIP-3009 authorization, pay THROUGH the MCP bridge via
 *      _meta["x402/payment"] (object payload), receive the Dilithium-3 / ML-DSA-65 proof, and VERIFY
 *      it OFFLINE. This is the only test that proves the full chain with real money.
 *
 * Run: npm run build && node test/x402-mcp-e2e.mjs        (add PAYER_PRIVATE_KEY for step D)
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { createRequire } from "module";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import crypto from "node:crypto";

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(__dirname, "../dist/index.js");
const TREASURY = "0xC13789e82661635d9Cea38a53A0390CF9939ef4f";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MSG = `x402-mcp prueba reina @ ${new Date().toISOString()}`;
const SERVED_DOMAIN = "FRACTALAI-x402-served-v1";

let fail = 0;
const check = (n, ok, d = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${n}${d ? ` — ${d}` : ""}`); if (!ok) fail++; };
const skip = (n, d) => console.log(`SKIP  ${n}${d ? ` — ${d}` : ""}`);
const parse = (r) => { try { return JSON.parse(r.content?.[0]?.text ?? "{}"); } catch { return {}; } };
const sha256hex = (s) => crypto.createHash("sha256").update(s, "utf8").digest("hex");
const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));

console.log("=== x402 ⇄ MCP — prueba reina (end-to-end) ===\n");

// ── A. _META PLUMBING (definitive, in-memory, no network) ─────────────────────
{
  const srv = new McpServer({ name: "echo", version: "0.0.0" });
  srv.registerTool("__echo_meta", { title: "echo", description: "echo extra._meta", inputSchema: {} },
    async (_args, extra) => ({ content: [{ type: "text", text: JSON.stringify({ meta: extra?._meta ?? null }) }] }));
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await srv.connect(st);
  const cli = new Client({ name: "echo-client", version: "0.0.0" });
  await cli.connect(ct);
  const r = await cli.callTool({ name: "__echo_meta", arguments: {}, _meta: { "x402/payment": { probe: 123 } } });
  const got = parse(r)?.meta?.["x402/payment"]?.probe;
  check("A. _meta plumbing: client callTool _meta → server extra._meta (the auto-pay channel)", got === 123, `probe=${got}`);
  await cli.close();
}

// ── B + C + D against the REAL server over stdio ──────────────────────────────
const transport = new StdioClientTransport({ command: process.execPath, args: [SERVER] });
const client = new Client({ name: "e2e", version: "0.0.0" });
try {
  await client.connect(transport);

  // B. discovery
  const cat = parse(await client.callTool({ name: "list_fractalai_proofs", arguments: {} }));
  check("B. discovery: list_fractalai_proofs returns the live catalog", (cat.count ?? 0) >= 7, `count=${cat.count}`);

  // C. challenge (canonical)
  const ch = await client.callTool({ name: "seal_ml_dsa", arguments: { message: MSG } });
  const chb = ch.structuredContent ?? parse(ch);
  const req = (chb.accepts ?? []).find((a) => a.extra?.assetTransferMethod === "eip3009") ?? (chb.accepts ?? [])[0];
  const reqAmount = req?.amount ?? req?.maxAmountRequired; // v2 `amount` / v1 `maxAmountRequired`
  // v2 challenge must carry x402Version:2 + a top-level `resource` object (the field the union schema requires).
  check("C. challenge: unpaid seal_ml_dsa returns canonical v2 PaymentRequired",
    ch.isError === true && chb.x402Version === 2 && Boolean(req) && Boolean(chb.resource?.url),
    `ver=${chb.x402Version} price=${reqAmount} resource=${chb.resource?.url ? "yes" : "no"}`);

  // D. PRUEBA REINA — real payment through the bridge (needs a funded payer)
  const pk = (process.env.PAYER_PRIVATE_KEY || "").trim();
  if (!pk) {
    skip("D. PRUEBA REINA (real payment → D3 proof)", "set PAYER_PRIVATE_KEY = a Base wallet with ~$0.05 USDC (no ETH; gasless)");
  } else {
    const { ethers } = require("ethers");
    const wallet = new ethers.Wallet(pk);
    const provider = new ethers.JsonRpcProvider("https://mainnet.base.org", 8453);
    const now = Math.floor(Date.now() / 1000);
    const auth = {
      from: wallet.address, to: TREASURY, value: String(reqAmount),
      validAfter: "0", validBefore: String(now + 600), nonce: "0x" + crypto.randomBytes(32).toString("hex"),
    };
    const domain = { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC };
    const types = { TransferWithAuthorization: [
      { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
    ] };
    const signature = await wallet.signTypedData(domain, types, auth);
    const paymentPayload = { x402Version: 1, scheme: "exact", network: "base", payload: { signature, authorization: auth } };

    console.log(`\n  paying 0.02 USDC from ${wallet.address.slice(0, 10)}… THROUGH the MCP bridge (gasless EIP-3009)…`);
    const paid = await client.callTool({ name: "seal_ml_dsa", arguments: { message: MSG }, _meta: { "x402/payment": paymentPayload } });
    const out = parse(paid);

    if (paid.isError) {
      check("D. PRUEBA REINA: real payment accepted", false, `route said: ${JSON.stringify(out).slice(0, 200)}`);
    } else {
      // verify the served Dilithium-3 signature OFFLINE (per-route domain-separated).
      const digestHex = sha256hex(MSG);
      const signed = new TextEncoder().encode(`${SERVED_DOMAIN}\nx402-sign\n${digestHex}`);
      const sigOk = out.algorithm === "ml-dsa-65" && ml_dsa65.verify(b64(out.signature), signed, b64(out.public_key)) === true;
      check("D. PRUEBA REINA: real payment → Dilithium-3 proof served + VERIFIED OFFLINE", sigOk, `algo=${out.algorithm}`);
      check("D. settlement receipt returned (_meta['x402/payment-response'])", Boolean(paid._meta?.["x402/payment-response"]));
      const txHash = out.payment?.txHash || out.payment?.transaction;
      if (txHash) {
        const rcpt = await provider.getTransactionReceipt(txHash).catch(() => null);
        check("D. USDC settled on-chain to the treasury (sovereign)", Boolean(rcpt && rcpt.status === 1), txHash);
      }
    }
  }
} finally {
  await client.close().catch(() => {});
}

console.log(fail === 0 ? "\nPRUEBA REINA: all runnable checks passed." : `\nPRUEBA REINA: ${fail} check(s) FAILED.`);
process.exit(fail === 0 ? 0 : 1);
