# AG2 (formerly AutoGen) + Agent Passport MCP

`discover_and_call.py` launches this MCP server as a subprocess from an
[AG2](https://github.com/ag2ai/ag2) agent via `MCPToolkit` /
`MCPStdioServerConfig`, lets AG2 discover the 12 tools, and calls the free
`lookup_agent` tool against the live FractalAI node.

No LLM API key is needed: the model is scripted with `ag2.testing.TestConfig`,
so the only outbound call is the MCP tool call itself.

```bash
python3.12 -m venv .venv
./.venv/bin/pip install "ag2[mcp]"
./.venv/bin/python discover_and_call.py
```

## Verified run

Verified on 2026-10-09 with `ag2` 1.1.2, `mcp` 2.3.0, Python 3.12,
`@fractalai/agent-passport-mcp` 0.2.5:

```
final: ok

lookup_agent ->
ToolResultEvent(name='lookup_agent', result=ToolResult(parts=[TextInput(
  content='{\n  "agents": [\n    {\n      "agent_id": "0xeb7b1116fbadd73e47cdb435fd24f6927...'
  (len=1859))], final=False)
```

A cold `npx` start occasionally times out before the handshake completes
(`MCPError: Connection closed`); re-run, or `npm i -g @fractalai/agent-passport-mcp`
first and set `command="agent-passport-mcp"`.

## Which tools cost money

Free: `lookup_agent` and `verify_passport` — the two the server's own start-up
banner reports as free (`list_fractalai_proofs`, which just reads the public
catalog, also answers without payment).

Paid (x402 / HTTP 402, USDC on Base): `issue_passport`, `witness_payment`,
`seal_ml_dsa`, `notarize_decision`, `prove_provenance`, `attest_training`,
`seal_cbom`, `verify_agent_kya`, `verify_proof`. Called without payment they
return the x402 payment challenge — they never fabricate a proof.

## Honest scope

FractalAI implements FIPS 204 ML-DSA-65 (NIST level 3). It is **not** FIPS 140-3
/ CMVP validated, **not** CNSA 2.0, and has had no external security audit.
Single validator, no paying customers yet. Pre-pilot and we say so.
