# Agent Passport — MCP server

The **free** tool a developer drops in, in ~5 lines, to **issue** and **independently verify**
a *verifiable passport* for an AI agent — over the [Model Context Protocol](https://modelcontextprotocol.io),
so it works in **LangChain, CrewAI, AutoGen, OpenAI Agents, Claude Desktop** — anything that speaks MCP.

It talks to the **real, public FractalAI deployment**: the live L1 JSON-RPC node at
`https://api.fractalai.net.co` (FRC-55 agent registry) and the web endpoints at
`https://fractalai.net.co` (attestations, receipt key, x402). **Nothing here is mocked.**

```bash
npx @fractalai/agent-passport-mcp
```

## Tools

| Tool | Cost | What it REALLY does today |
|------|------|---------------------------|
| `verify_passport` | **free** | Given an attestation permalink / `0x` hash (and optionally the receipt JSON): recomputes the content hashes, reconstructs the exact canonical signed message, verifies the **ML-DSA-65 (NIST FIPS 204)** signature **100% offline** against the published `/api/x402/receipt-key`, verifies the **Dilithium-2** signature server-assisted with a tamper negative-control, and reads the agent's **FRC-55 on-chain** state. Returns `{ valid, algorithm, checks[], anchored, decision, agent }`. |
| `issue_passport` | **x402 ($0.05 USDC)** | Binds an `agent_id` + a **signed assertion** + a re-verifiable permalink: resolves the agent on the FRC-55 registry (if it's an on-chain id) and seals the assertion through the **real x402 attest-decision** flow (Dilithium-2 signed, Black-Box chained, anchored on the L1). Without a `payment_tx_hash` it returns the payment challenge — it never fabricates a passport. |
| `lookup_agent` | **free** | Public FRC-55 registry read on the live node: `fractal_getAgent` for one agent (name, owner, status, model, `total_calls`, `rating`, `total_ratings`, `created_at`) or `fractal_listAgents` for all, always with `fractal_getAgentStats`. |
| `list_fractalai_proofs` | **free** | Self-describing discovery: reads the canonical `/.well-known/x402.json` live and returns the full proof catalog (price, algorithm, endpoint, what each proves) — one call maps the whole x402 surface and auto-heals if it changes, since it reflects the live source of truth rather than a hardcoded copy. |

### x402-paid tools (v0.2.0) — post-quantum proofs, pay-per-call

The 8 supported FractalAI x402 routes are surfaced as **auto-payable** MCP tools. An x402-aware wallet client
signs an EIP-3009 authorization and pays in **USDC on Base** using the standard `_meta["x402/payment"]`
convention. Each **served** signature is **ML-DSA-65 / Dilithium-3 (NIST FIPS 204)** and verifiable
**offline**; each also **attempts** an on-chain anchor on FractalAI's L1 (the anchor signature is
Dilithium-2 / ML-DSA-44-class, pending the gated consensus cut-over — see "Honest scope"). Uses the
FIPS-204-standardized algorithm via audited `@noble/post-quantum` (not a FIPS-validated CMVP module).
Call any tool **without** payment first to get the exact price + payment challenge.

| Tool | Price | What it does |
|------|------|---------------|
| `seal_ml_dsa` | $0.02 | Post-quantum signature over any message/hash — durable, quantum-safe, offline-verifiable. |
| `verify_proof` | $0.01 | Verify a signature (auto-detects ML-DSA-65 or Dilithium-2). The floor primitive for any proof pipeline. |
| `verify_agent_kya` | $0.03 | Know-Your-Agent: verify another agent's credential + live FRC-55 reputation before you trust/pay it. |
| `notarize_decision` | $0.05 | Notarize an AI decision (input, output, model) → auditable, non-repudiable, on-chain (EU AI Act Art. 12). |
| `prove_provenance` | $0.05 | Provenance seal over a dataset/content hash + drand timestamp + on-chain anchor. |
| `attest_training` | $0.05 | C2PA training-provenance manifest for a model, post-quantum signed. |
| `seal_cbom` | $0.05 | Seal a CycloneDX CBOM (crypto inventory) — CNSA 2.0 / procurement PQC-readiness disclosure. |

Payment note: paid tools accept the standard `_meta["x402/payment"]` (auto-pay) and also a plain
`payment` string arg (base64 X-PAYMENT) as a universal fallback. Nothing is fabricated — the tools
proxy to the live routes and relay exactly what they return, honest scope included.

## Honest scope (read this — project Regla 4)

A **valid passport** proves an **identity + a specific attested assertion** are cryptographically
intact over the exact signed bytes, that the record is internally consistent, and that it is
**anchored on FractalAI's L1**. It does **NOT** prove:

- that the assertion is **true**, or that the agent's decision/action was **correct**;
- any **decentralized / consensus-scored reputation** — `issue_passport` does **not** register reputation;
- `lookup_agent` ratings are the **registry's own counters** as reported by the node, not an independent audit.

Signature checks are labeled by trust model: **`[independent]`** = computed locally, does not trust
the FractalAI server (the offline ML-DSA-65 check, content hashes); **`[server-assisted]`** = calls a
FractalAI endpoint (the Dilithium-2 `/api/proofmind/verify` check). The ML-DSA-65 verification uses the
FIPS-204-standardized algorithm via the audited `@noble/post-quantum` library — this is **not** a
FIPS-validated (CMVP) module.

### What is real **today** vs roadmap

- **Real today:** offline ML-DSA-65 verification against the published key; server-assisted Dilithium-2
  verification + tamper control; FRC-55 on-chain agent reads; the real x402 402→pay→seal flow for issuing.
- **Roadmap (not claimed as done):** server-issued attestations are currently self-signed by the server
  key and anchored on FractalAI's own L1; full on-chain consensus validation and a decentralized,
  consensus-scored reputation are future milestones. The `ml_dsa65` detached signature is delivered to
  pilot integrations today (pass it via the `receipt` argument) and is being rolled into the public API.

## Use it

You don't need to install or build anything — `npx` fetches and runs the published package
directly (see the config block above). No account, no API key.

## Contributing (building from source)

Only needed if you're working on the server itself, inside the FractalAI monorepo:

```bash
cd integrations/agent-passport-mcp
npm install
npm run build      # tsc → dist/
npm test           # handshake: server stands up, tools respond, ML-DSA-65 round-trips
```

## Configure in an MCP client

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "agent-passport": { "command": "npx", "args": ["-y", "@fractalai/agent-passport-mcp"] }
  }
}
```

### Environment

- `FRACTALAI_BASE_URL` — web endpoint base (default `https://fractalai.net.co`).
- `FRACTALAI_RPC_URL` — L1 JSON-RPC node (default `https://api.fractalai.net.co`).
- `AGENT_PASSPORT_AUTODEMO` — on connect, the server makes one real, free call to the live node
  (`fractal_getAgentStats`) and logs the result to stderr, so you can see immediately that this
  isn't mocked. Fire-and-forget — it never delays or blocks the MCP handshake. Set to `0` to disable.

## 5-line examples (per framework)

All of these run the **same** MCP server (`npx @fractalai/agent-passport-mcp`) over stdio and call the tools.

**LangChain (Python)** — `langchain-mcp-adapters`:
```python
from langchain_mcp_adapters.client import MultiServerMCPClient
client = MultiServerMCPClient({"agent_passport": {"command": "npx", "args": ["-y", "@fractalai/agent-passport-mcp"], "transport": "stdio"}})
tools = await client.get_tools()   # verify_passport, issue_passport, lookup_agent
agent = create_react_agent(model, tools)
await agent.ainvoke({"messages": "Verify passport https://fractalai.net.co/attestation/0x…"})
```

**CrewAI (Python)** — `crewai-tools` MCP adapter:
```python
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters
params = StdioServerParameters(command="npx", args=["-y", "@fractalai/agent-passport-mcp"])
with MCPServerAdapter(params) as tools:
    Agent(role="Auditor", tools=tools, goal="Verify agent passports", backstory="...")
```

**AutoGen (Python)** — `autogen-ext` MCP workbench:
```python
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools
params = StdioServerParams(command="npx", args=["-y", "@fractalai/agent-passport-mcp"])
tools = await mcp_server_tools(params)   # verify_passport / issue_passport / lookup_agent
agent = AssistantAgent("auditor", model_client=client, tools=tools)
```

**OpenAI Agents SDK (Python)**:
```python
from agents import Agent
from agents.mcp import MCPServerStdio
async with MCPServerStdio(params={"command": "npx", "args": ["-y", "@fractalai/agent-passport-mcp"]}) as server:
    agent = Agent(name="Auditor", instructions="Verify and issue agent passports.", mcp_servers=[server])
```

## Independent, no-framework verification

Because a receipt is designed for **third-party** verification, you don't even need this server (or
any FractalAI code) to check one — just `@noble/post-quantum` and the public key directory:

```js
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

// 1. Pin the trusted key(s) from the signed, ML-DSA-65-governed directory (fetch once, cache):
const dir = await (await fetch('https://fractalai.net.co/.well-known/x402-receipt-keys')).json();
// (dir.signature / dir.directory_public_key let you verify the directory itself is unmodified —
// see @fractalai/pqc-agent-receipts-conformance for a full conformance-checked example.)

// 2. Given ANY served receipt — e.g. the response of a paid /api/x402/* call — verify offline:
const { signature, signed_message, public_key } = receipt; // fields returned by every x402 route
const valid = ml_dsa65.verify(
  Buffer.from(signature, 'base64'),
  new TextEncoder().encode(signed_message),
  Buffer.from(public_key, 'base64'),
);
console.log('receipt valid:', valid); // true only if the exact bytes were signed by that key
```

For a battle-tested, adversarially-vectored version of this same check (genuine + tampered +
wrong-key forgery vectors across x402/SAR/ACP/JOSE/W3C-VC profiles), see
[`@fractalai/pqc-agent-receipts-conformance`](https://www.npmjs.com/package/@fractalai/pqc-agent-receipts-conformance)
(`npx pqc-receipt-check`).

## License

MIT

## Automated commerce onboarding (0.2.5)

Call `list_fractalai_proofs` first. It returns the live catalog, payment requirements, input schemas and a supported MCP tool or an explicit HTTP integration path. Prices in discovery are informational: request a fresh challenge before authorizing a purchase. The MCP server does not hold buyer funds; automatic payment requires a compatible wallet client with a configured spending policy.

`witness_payment` accepts `seal_body`, optional `request_binding` and `settlement_tx`, and the standard x402 payment metadata. Build bound requests with the witness SDK; persist the request and authorization before submitting. The bridge forwards once and never creates a replacement authorization after a timeout. Verify delivered evidence using an independently trusted key. This tool does not replace the buyer's durable recovery store.

Run `npm run test:commerce` for deterministic MCP transport tests without network or payments.
