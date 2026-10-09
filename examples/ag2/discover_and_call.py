"""Use the FractalAI Agent Passport MCP server from an AG2 agent.

Runs with no LLM API key: the model is scripted with ``ag2.testing.TestConfig``
so the only network traffic is the MCP tool call itself, against the live
FractalAI node. That makes the result reproducible by anyone.

    python -m venv .venv && ./.venv/bin/pip install "ag2[mcp]"
    ./.venv/bin/python discover_and_call.py

Only ``lookup_agent`` and ``verify_passport`` are free. The other nine tools are
x402 (HTTP 402) paid resources priced in USDC on Base; called without payment
they return the payment challenge, never a fabricated proof.

Honest scope: FractalAI implements FIPS 204 ML-DSA-65 (NIST level 3). It is NOT
FIPS 140-3 / CMVP validated, NOT CNSA 2.0, and has had no external security
audit. Single validator, no paying customers yet. Pre-pilot.
"""

import asyncio
import os

from ag2 import Agent
from ag2.events import ToolCallEvent
from ag2.testing import TestConfig
from ag2.tools import MCPStdioServerConfig, MCPToolkit

CAPTURED: dict[str, object] = {}


async def spy(call_next, event, context):
    """Tool middleware: keep whatever the MCP server answered, then pass it on."""
    result = await call_next(event, context)
    CAPTURED[event.name] = result
    return result


async def main() -> None:
    env = dict(os.environ)
    env["AGENT_PASSPORT_AUTODEMO"] = "0"  # skip the server's start-up demo call

    toolkit = MCPToolkit(
        MCPStdioServerConfig(
            command="npx",
            args=["-y", "@fractalai/agent-passport-mcp@0.2.5"],
            env=env,
            server_label="fractalai",
        ),
        middleware=[spy],
    )

    agent = Agent(
        name="pqc-client",
        config=TestConfig(ToolCallEvent(name="lookup_agent", arguments="{}"), "ok"),
        tools=[toolkit],
    )

    reply = await agent.ask("List the agents registered on the FRC-55 registry.")
    print("final:", await reply.content())
    for name, result in CAPTURED.items():
        print(f"\n{name} ->\n{result}")


if __name__ == "__main__":
    asyncio.run(main())
