// REVISION ADVERSARIAL Fase B.2 (2026-10-12) — PoC contra las tools MCP del registro. REAL ML-DSA-65.
// Run: npm run build && node --test test/registry-attacks.mjs
// [HALLAZGO] = pasaba mientras el defecto existia; tras el arreglo (#4, #7) cada assert esta INVERTIDO y
// el test pasa SOLO con el arreglo.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { jcs, sha256Hex, b64url, kidOf, manifestId, registerRegistryTools, resetIndexFreshnessState, checkIndexFreshness, MANIFEST_SIGN_PREFIX, INDEX_SIGN_PREFIX } from '../dist/registry-tools.js';

const base = 'https://fractalai.net.co';
const AGENT = '0x' + '37'.repeat(32);
const agentKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x11));
const notaryKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x33));
const NOW = Math.floor(Date.now() / 1000);
const PUB = b64url(agentKp.publicKey);

function manifest() {
  const u = {
    schema: 'fractalai-agent-manifest/1', version: 1, prev_manifest_id: null, issued_at: NOW, expires_at: NOW + 86400,
    agent: { id: AGENT, did: `did:web:fractalai.net.co:agents:${AGENT}`, name: 'MIDAS', owner: 'fractal1_pq_' + 'ab'.repeat(20), status: 'Active', passport_url: `${base}/api/agents/registry/${AGENT}/passport` },
    keys: { signing: { alg: 'ML-DSA-65', kid: kidOf(agentKp.publicKey), pub: PUB }, receipts_directory: `${base}/.well-known/x402-receipt-keys`, jwks: `${base}/.well-known/jwks.json` },
    registry: { identity_root: '0x' + '27'.repeat(32), height: 1, signer_kid: '0'.repeat(16) },
    capabilities: [{ id: 'midas-attest', description: 'x', x402: { resource: `${base}/api/x402/midas-attest` }, sandbox: false }],
    operations: { intent_schema: 'commerce-intent/1', receipt: 'delivery-receipt v0.2.1', authorization: 'X-Agent-Authorization v2' },
    endpoints: { http: base, rpc: 'https://api.fractalai.net.co', mcp: '@fractalai/agent-passport-mcp', verify: '/api/passport/verify' },
  };
  const id = manifestId(u);
  const sig = ml_dsa65.sign(new TextEncoder().encode(MANIFEST_SIGN_PREFIX + id), agentKp.secretKey);
  return { ...u, manifest_id: id, signature: { alg: 'ML-DSA-65', kid: kidOf(agentKp.publicKey), sig: b64url(sig) } };
}
function signIndex(agents, issued_at, seq = issued_at, expires_at = issued_at + 300) {
  const idx = { schema: 'fractalai-agents-index/1', issued_at, expires_at, seq, registry: { identity_root: '0x' + '27'.repeat(32), height: 1, signer_kid: null }, agents };
  const sig = ml_dsa65.sign(new TextEncoder().encode(INDEX_SIGN_PREFIX + sha256Hex(jcs(idx))), notaryKp.secretKey);
  return { ...idx, signature: { alg: 'ML-DSA-65', kid: kidOf(notaryKp.publicKey), sig: b64url(sig) } };
}
async function bridge(t, fetcher) {
  const originalFetch = globalThis.fetch;
  const originalEnv = { ...process.env };
  globalThis.fetch = fetcher;
  process.env.FRACTALAI_PINNED_RECEIPT_KEY = Buffer.from(notaryKp.publicKey).toString('base64');
  resetIndexFreshnessState();
  const server = new McpServer({ name: 'attack', version: '0.0.0' });
  registerRegistryTools(server);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'victim', version: '0.0.0' });
  await client.connect(ct);
  t.after(async () => { await client.close(); await server.close(); globalThis.fetch = originalFetch; process.env = originalEnv; });
  return client;
}
const parse = (r) => JSON.parse(r.content[0].text);
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
const entry = (m) => ({ id: AGENT, name: 'MIDAS', did: m.agent.did, manifest_url: `${base}/api/agents/registry/${AGENT}`, manifest_id: m.manifest_id, version: 1, kid: m.keys.signing.kid, status: 'Active' });

test('[HALLAZGO→ARREGLADO #4] anti-rollback del indice: tras ver uno nuevo (agente revocado), un indice VIEJO firmado se RECHAZA (expirado y rollback), sin agents', async (t) => {
  const m = manifest();
  const fresh = signIndex([], NOW);                    // hoy: el agente ya NO es vigente
  const stale = signIndex([entry(m)], NOW - 30 * 86400); // hace 30 dias: el agente si lo era
  let serve = fresh;
  const client = await bridge(t, async (url) => (/agents\.json$/.test(String(url)) ? json(serve) : json({}, 404)));
  const a = parse(await client.callTool({ name: 'list_agents', arguments: {} }));
  assert.equal(a.index_signature_verified, true); assert.equal(a.count, 0); assert.equal(a.expires_at, NOW + 300); assert.equal(a.seq, NOW);
  serve = stale; // espejo/caché/MITM reproduce el indice de hace 30 dias
  let r = await client.callTool({ name: 'list_agents', arguments: {} });
  let b = parse(r);
  assert.equal(r.isError, true);
  assert.equal(b.error, 'index_expired', 'firmado de verdad, pero expirado: no es dato');
  assert.equal(b.agents, undefined);
  // un indice firmado, NO expirado, pero mas viejo que el ultimo visto (issued_at o seq menor) → rollback
  serve = signIndex([entry(m)], NOW - 10, NOW - 10, NOW + 290);
  r = await client.callTool({ name: 'list_agents', arguments: {} });
  b = parse(r);
  assert.equal(r.isError, true); assert.equal(b.error, 'index_rollback'); assert.equal(b.agents, undefined);
  serve = signIndex([entry(m)], NOW + 5, NOW - 1); // issued_at mas nuevo pero seq menor → rollback igual
  r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'index_rollback');
  // uno realmente mas nuevo (issued_at y seq >=) si se acepta y sube la marca
  serve = signIndex([entry(m)], NOW + 5, NOW + 5);
  r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, undefined); assert.equal(parse(r).count, 1);
  serve = fresh; // y ahora el "fresh" original es rollback
  r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'index_rollback');
  // sin expires_at/seq (indice de la forma vieja) → malformado, nunca aceptado
  const legacy = { schema: 'fractalai-agents-index/1', issued_at: NOW + 9, registry: { identity_root: null, height: null, signer_kid: null }, agents: [] };
  const legacySig = ml_dsa65.sign(new TextEncoder().encode(INDEX_SIGN_PREFIX + sha256Hex(jcs(legacy))), notaryKp.secretKey);
  serve = { ...legacy, signature: { alg: 'ML-DSA-65', kid: kidOf(notaryKp.publicKey), sig: b64url(legacySig) } };
  r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'index_malformed');
  assert.equal(checkIndexFreshness({ issued_at: NOW + 1000, expires_at: NOW + 1300, seq: 1 }, NOW, null).reason, 'index_issued_in_future');
});

test('[HALLAZGO→ARREGLADO #4] list_agents NO devuelve agents[] cuando la firma del indice no verifica: solo error', async (t) => {
  const forged = { ...signIndex([], NOW), agents: [{ id: '0x' + 'ee'.repeat(32), name: 'EVIL', manifest_url: 'https://evil.example/m', status: 'Active' }] };
  const client = await bridge(t, async (url) => (/agents\.json$/.test(String(url)) ? json(forged) : json({}, 404)));
  const r = await client.callTool({ name: 'list_agents', arguments: {} });
  const d = parse(r);
  assert.equal(r.isError, true);
  assert.equal(d.index_signature_verified, false);
  assert.equal(d.error, 'index_signature_invalid');
  assert.equal(d.agents, undefined);
  assert.equal(JSON.stringify(d).includes('EVIL'), false);
});

test('[HALLAZGO→ARREGLADO #7] verify_agent_manifest → ok:false (isError) con signature_ok:true, passport_valid:false, agent_active:false cuando el pasaporte es invalido y el agente esta Destroyed', async (t) => {
  const m = manifest();
  const client = await bridge(t, async (url) => (/\/passport$/.test(String(url))
    ? json({ agent_id: AGENT, agent_status: 'Destroyed', valid: false, current_key: { alg: 'MlDsa65', kid: m.keys.signing.kid, pub: PUB } })
    : json({}, 404)));
  const r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m } });
  const d = parse(r);
  assert.equal(r.isError, true);
  assert.equal(d.ok, false);
  assert.equal(d.signature_ok, true);
  assert.equal(d.passport_valid, false);
  assert.equal(d.agent_active, false);
  assert.equal(d.agent_status, 'Destroyed');
  assert.deepEqual(d.not_ok_because, ['passport_valid=false (node verdict)', 'agent_active=false (status Destroyed)']);
});

test('[#10] un served-proof del notario (comprable por centavos en /api/x402/sign sobre un digest elegido) NUNCA se acepta como firma del indice, con cualquier route id', async (t) => {
  const m = manifest();
  const unsignedIdx = { schema: 'fractalai-agents-index/1', issued_at: NOW, expires_at: NOW + 300, seq: NOW, registry: { identity_root: '0x' + '27'.repeat(32), height: 1, signer_kid: null }, agents: [entry(m)] };
  const hash = sha256Hex(jcs(unsignedIdx));
  const servedProof = (route) => `FRACTALAI-x402-served-v1\n${route}\n${hash}`; // server's served-proof message format
  const dressed = (msg) => ({ ...unsignedIdx, signature: { alg: 'ML-DSA-65', kid: kidOf(notaryKp.publicKey), sig: b64url(ml_dsa65.sign(new TextEncoder().encode(msg), notaryKp.secretKey)) } });
  const candidates = [servedProof('sign'), servedProof('agents-index'), servedProof('fractalai-agents-index/1'), hash, `fractalai-agents-index/1\n${hash}\n`, `FRACTALAI-x402-served-v1\n${hash}`];
  let serve = dressed(candidates[0]);
  const client = await bridge(t, async (url) => (/agents\.json$/.test(String(url)) ? json(serve) : json({}, 404)));
  for (const c of candidates) {
    serve = dressed(c);
    const r = await client.callTool({ name: 'list_agents', arguments: {} });
    const d = parse(r);
    assert.equal(r.isError, true, `aceptado: ${JSON.stringify(c)}`);
    assert.equal(d.error, 'index_signature_invalid');
    assert.equal(d.agents, undefined);
  }
  // the genuine index message (and only it) verifies
  serve = dressed(INDEX_SIGN_PREFIX + hash);
  const r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, undefined);
  assert.equal(parse(r).count, 1);
});

test('[#11] un manifest bien firmado cuyo jwks/rpc/verify apuntan fuera del origen oficial NO verifica offline (ni con clave del llamador ni asistido por el registro)', async (t) => {
  const u = { ...manifest() };
  delete u.manifest_id; delete u.signature;
  u.keys = { ...u.keys, jwks: 'https://fractalai.net.co.evil.example/.well-known/jwks.json' };
  u.endpoints = { ...u.endpoints, rpc: 'https://evil.example', verify: 'https://evil.example/api/passport/verify' };
  const id = manifestId(u);
  const evil = { ...u, manifest_id: id, signature: { alg: 'ML-DSA-65', kid: kidOf(agentKp.publicKey), sig: b64url(ml_dsa65.sign(new TextEncoder().encode(MANIFEST_SIGN_PREFIX + id), agentKp.secretKey)) } };
  const client = await bridge(t, async (url) => (/\/passport$/.test(String(url))
    ? json({ agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa65', kid: evil.keys.signing.kid, pub: PUB } })
    : json({}, 404)));
  for (const args of [{ manifest: evil, pubkey_b64url: PUB }, { manifest: evil }]) {
    const r = await client.callTool({ name: 'verify_agent_manifest', arguments: args });
    const d = parse(r);
    assert.equal(r.isError, true);
    assert.equal(d.ok, false);
    assert.equal(d.signature_ok, false, 'signature_ok folds in the pin check: a foreign locator is not a verified manifest');
    const pin = d.checks.find((c) => /official FractalAI locators/.test(c.name));
    assert.equal(pin.pass, false);
    assert.equal(pin.detail, 'not pinned: keys.jwks, endpoints.rpc, endpoints.verify');
    assert.equal(d.checks.find((c) => /verifies OFFLINE/.test(c.name)).pass, true, 'the ML-DSA-65 signature itself is genuine — that is the point');
  }
});
