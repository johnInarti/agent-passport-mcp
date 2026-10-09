import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { registerX402Tools, buildProofCatalog } from '../dist/x402-tools.js';

const base = 'https://fractalai.net.co';
const challenge = { x402Version: 2, resource: { url: `${base}/api/x402/witness` }, accepts: [{ scheme: 'exact', network: 'eip155:8453', amount: '5000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: 'synthetic-recipient' }] };
const seal = { schema: 'synthetic', amount: '20000', response_sha256: '11'.repeat(32) };
async function bridge(t, fetcher) {
  const original = globalThis.fetch;
  globalThis.fetch = fetcher;
  const server = new McpServer({ name: 'commerce-test', version: '0.0.0' });
  registerX402Tools(server);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'buyer-test', version: '0.0.0' });
  await client.connect(ct);
  t.after(async () => { await client.close(); await server.close(); globalThis.fetch = original; });
  return client;
}

test('live catalog routes witness to a real MCP tool; unsupported products retain HTTP onboarding', () => {
  const rows = ['witness', 'midas-attest', 'sentinel-credit'].map(route => ({ resource: `${base}/api/x402/${route}`, method: 'POST', accepts: challenge.accepts }));
  const result = buildProofCatalog(rows, base);
  assert.equal(result[0].mcp_tool, 'witness_payment');
  assert.equal(result[0].price_usdc, 0.005);
  assert.deepEqual(result[0].payment_requirements, challenge.accepts);
  for (const row of result.slice(1)) { assert.equal(row.mcp_tool, null); assert.equal(row.integration, 'http'); assert.match(row.next_action, /HTTP/); }
});

test('foreign origin, altered paths and other methods never map to a trusted MCP tool', () => {
  const rows = [
    { resource: 'https://example.com/api/x402/witness', method: 'POST' },
    { resource: `${base}/api/x402/witness?other=1`, method: 'POST' },
    { resource: `${base}/api/x402/witness`, method: 'GET' },
    { resource: `${base}/api/x402/constructor`, method: 'POST' },
  ];
  for (const row of buildProofCatalog(rows, base)) assert.equal(row.mcp_tool, null);
  assert.throws(() => buildProofCatalog({}, base));
});

test('unpaid witness preserves canonical v2 challenge through the actual MCP transport', async t => {
  let calls = 0;
  const client = await bridge(t, async (url, options) => {
    calls++; assert.match(String(url), /\/api\/x402\/witness$/);
    assert.equal(options.headers['PAYMENT-SIGNATURE'], undefined);
    assert.deepEqual(JSON.parse(options.body), { seal_body: seal });
    return new Response(JSON.stringify(challenge), { status: 402 });
  });
  const tools = (await client.listTools()).tools;
  assert.ok(tools.some(tool => tool.name === 'witness_payment'));
  const result = await client.callTool({ name: 'witness_payment', arguments: { seal_body: seal } });
  assert.equal(result.isError, true); assert.deepEqual(result.structuredContent, challenge);
  assert.deepEqual(result._meta['x402/payment-required'], challenge); assert.equal(calls, 1);
});

test('buyer authorization and recovery fields survive one forwarding operation unchanged', async t => {
  const authorization = { x402Version: 2, payload: { signature: 'synthetic-only', authorization: { nonce: '0x' + '22'.repeat(32) } } };
  const args = { seal_body: seal, request_binding: { version: 1, salt: '0x' + '33'.repeat(32) }, settlement_tx: '0x' + '44'.repeat(32) };
  let calls = 0;
  const client = await bridge(t, async (_url, options) => {
    calls++; assert.deepEqual(JSON.parse(options.body), args);
    assert.deepEqual(JSON.parse(Buffer.from(options.headers['PAYMENT-SIGNATURE'], 'base64')), authorization);
    return new Response(JSON.stringify({ seal: { synthetic: true }, payment: { transaction: args.settlement_tx } }));
  });
  const result = await client.callTool({ name: 'witness_payment', arguments: args, _meta: { 'x402/payment': authorization } });
  assert.notEqual(result.isError, true); assert.equal(calls, 1);
  assert.equal(result._meta['x402/payment-response'].transaction, args.settlement_tx);
});

test('network failure never retries or manufactures a receipt', async t => {
  let calls = 0;
  const client = await bridge(t, async () => { calls++; throw Error('response lost'); });
  const result = await client.callTool({ name: 'witness_payment', arguments: { seal_body: seal, payment: 'synthetic' } });
  assert.equal(result.isError, true); assert.equal(calls, 1); assert.equal(result._meta, undefined);
});

test('UTF-8 byte limit rejects multibyte oversized requests before any network call', async t => {
  let calls = 0;
  const client = await bridge(t, async () => { calls++; throw Error('must not fetch'); });
  const result = await client.callTool({ name: 'witness_payment', arguments: { seal_body: { text: '漢'.repeat(90000) } } });
  assert.equal(result.isError, true); assert.match(result.content[0].text, /input too large/); assert.equal(calls, 0);
});
