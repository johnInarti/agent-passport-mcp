// REVISION ADVERSARIAL #4 (2026-10-12) — PoC MCP. REAL ML-DSA-65.
// Run: npm run build && node --test test/registry-attacks-r4.mjs
// [HALLAZGO R4-1] = pasa mientras el defecto exista; al arreglarlo, invertir.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { b64url, kidOf, manifestId, registerRegistryTools, resetIndexFreshnessState, MANIFEST_SIGN_PREFIX } from '../dist/registry-tools.js';

const base = 'https://fractalai.net.co';
const VICTIM = '0x' + '37'.repeat(32);
const attackerKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x22));
const NOW = Math.floor(Date.now() / 1000);
const PUB = b64url(attackerKp.publicKey);

function forgedManifest() {
  const u = {
    schema: 'fractalai-agent-manifest/1', version: 1, prev_manifest_id: null, issued_at: NOW, expires_at: NOW + 86400,
    agent: { id: VICTIM, did: `did:web:fractalai.net.co:agents:${VICTIM}`, name: 'MIDAS', owner: 'fractal1_pq_' + 'ab'.repeat(20), status: 'Active', passport_url: `${base}/api/agents/registry/${VICTIM}/passport` },
    keys: { signing: { alg: 'ML-DSA-65', kid: kidOf(attackerKp.publicKey), pub: PUB }, receipts_directory: `${base}/.well-known/x402-receipt-keys`, jwks: `${base}/.well-known/jwks.json` },
    registry: { identity_root: '0x' + '27'.repeat(32), height: 1, signer_kid: '0'.repeat(16) },
    capabilities: [{ id: 'midas-attest', description: 'x', x402: { resource: `${base}/api/x402/midas-attest` }, sandbox: false }],
    operations: { intent_schema: 'commerce-intent/1', receipt: 'delivery-receipt v0.2.1', authorization: 'X-Agent-Authorization v2' },
    endpoints: { http: base, rpc: 'https://api.fractalai.net.co', mcp: '@fractalai/agent-passport-mcp', verify: '/api/passport/verify' },
  };
  const id = manifestId(u);
  const sig = ml_dsa65.sign(new TextEncoder().encode(MANIFEST_SIGN_PREFIX + id), attackerKp.secretKey);
  return { ...u, manifest_id: id, signature: { alg: 'ML-DSA-65', kid: kidOf(attackerKp.publicKey), sig: b64url(sig) } };
}
async function bridge(t, fetcher) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetcher;
  resetIndexFreshnessState();
  const server = new McpServer({ name: 'attack', version: '0.0.0' });
  registerRegistryTools(server);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'victim', version: '0.0.0' });
  await client.connect(ct);
  t.after(async () => { await client.close(); await server.close(); globalThis.fetch = originalFetch; });
  return client;
}
const parse = (r) => JSON.parse(r.content[0].text);
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

test('[HALLAZGO→ARREGLADO R4-1 MEDIO] verify_agent_manifest: agente NO registrado — tanto con la forma PRE-R4 de /passport (registered:false + valid:true, registro viejo/hostil) como con la forma R4 (valid:false, binding_unverified) → verdict "not_current", ok:false, isError; `current` exige registered===true o continuity.ok===true', async (t) => {
  const m = forgedManifest();
  // forma EXACTA de GET /api/agents/registry/<id>/passport (servidor pre-R4) para un id sin filas (registro pre-R4 u hostil)
  let passport = {
    agent_id: VICTIM, registered: false, agent_status: 'Active', valid: true, reasons: [],
    current_key: { alg: 'MlDsa65', kid: kidOf(attackerKp.publicKey), pub: PUB },
    agent_binding: { present: false, ok: false, reason: 'agent_binding_absent' },
    continuity: { ok: null, reason: 'not_registered', bound_canonical_key: null },
  };
  const client = await bridge(t, async (url) => (/\/passport$/.test(String(url)) ? json(passport) : json({}, 404)));
  let r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m } });
  let d = parse(r);
  assert.equal(r.isError, true);
  assert.equal(d.ok, false);
  assert.equal(d.verdict, 'not_current');
  assert.equal(d.passport_valid, false);
  assert.equal(d.signature_ok, true); // la firma del atacante sobre su propio manifiesto es real — pero nada liga VICTIM ↔ esa clave
  assert.ok(d.passport_reasons.includes('not_registered'));
  r = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: VICTIM } });
  // (sin /registry/<id> el fetch da 404 → error; lo relevante es que verify nunca dijo current)
  assert.equal(r.isError, true);
  // forma R4 del registro: valid:false con binding_unverified → igual not_current, razon relayada
  passport = { ...passport, valid: false, reasons: ['binding_unverified'], first_binding: { ok: false, reason: 'no_trusted_or_independent_channel' } };
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m } });
  d = parse(r);
  assert.equal(r.isError, true); assert.equal(d.ok, false); assert.equal(d.verdict, 'not_current');
  assert.deepEqual(d.passport_reasons, ['binding_unverified']);
  // un agente REGISTRADO (fila + continuidad ok) con valid:true sigue siendo current
  passport = { ...passport, registered: true, valid: true, reasons: [], continuity: { ok: true, reason: null, bound_canonical_key: 'ab'.repeat(32) } };
  d = parse(await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m } }));
  assert.equal(d.ok, true); assert.equal(d.verdict, 'current');
  // sin fila pero con continuidad ok (p. ej. respuesta de un registro que ya la evaluo) tambien cuenta como ligado
  passport = { ...passport, registered: false, continuity: { ok: true, reason: null } };
  d = parse(await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m } }));
  assert.equal(d.ok, true);
});
