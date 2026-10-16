// REVISION ADVERSARIAL #5 FINAL (2026-10-12) — PoC MCP. REAL ML-DSA-65 + ML-DSA-44.
// Run: npm run build && node --test test/registry-attacks-r5.mjs
// [R4-n ARREGLADO] = assert de review4 invertido; [RESISTE] = lo que aguanta.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ml_dsa65, ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { b64url, kidOf, manifestId, registerRegistryTools, resetIndexFreshnessState, verifyManifestOffline, MANIFEST_SIGN_PREFIX } from '../dist/registry-tools.js';

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


const k44 = ml_dsa44.keygen(new Uint8Array(32).fill(0x44));
const basePassport = (over = {}) => ({
  agent_id: VICTIM, registered: false, agent_status: 'Active', valid: true, reasons: [],
  current_key: { alg: 'MlDsa65', kid: kidOf(attackerKp.publicKey), pub: PUB },
  agent_binding: { present: false, ok: false, reason: 'agent_binding_absent' },
  continuity: { ok: null, reason: 'not_registered', bound_canonical_key: null },
  ...over,
});
async function verifyWith(t, passport, args = {}) {
  const client = await bridge(t, async (url) => (/\/passport$/.test(String(url)) ? json(passport) : json({}, 404)));
  const r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: forgedManifest(), ...args } });
  return { r, d: parse(r) };
}

test('[R4-1 ARREGLADO] verify_agent_manifest: id NO registrado con valid:true (registry pre-R4 o mintiendo) → not_current; passport_reasons ⊇ not_registered', async (t) => {
  const { r, d } = await verifyWith(t, basePassport());
  assert.equal(r.isError, true);
  assert.equal(d.ok, false);
  assert.equal(d.verdict, 'not_current');
  assert.equal(d.passport_valid, false);
  assert.ok(d.passport_reasons.includes('not_registered'));
});

test('[R4-1 ARREGLADO] forma del servidor: registered:false + valid:false + binding_unverified → not_current, reasons relayed', async (t) => {
  const { d } = await verifyWith(t, basePassport({ valid: false, reasons: ['binding_unverified'], first_binding: { ok: false, reason: 'no_trusted_or_independent_channel', channels: '1 channel(s): fractalai.net.co' } }));
  assert.equal(d.verdict, 'not_current');
  assert.ok(d.passport_reasons.includes('binding_unverified'));
});

test('[RESISTE] "bound" exige registered === true o continuity.ok === true EXACTOS: "true", 1, {ok:"true"} no cuentan', async (t) => {
  for (const over of [{ registered: 'true' }, { registered: 1 }, { continuity: { ok: 'true' } }, { continuity: { ok: 1 } }, { registered: undefined, continuity: undefined }]) {
    const { d } = await verifyWith(t, basePassport(over));
    assert.equal(d.verdict, 'not_current', JSON.stringify(over));
  }
  const { d } = await verifyWith(t, basePassport({ registered: true, continuity: { ok: true } }));
  assert.equal(d.verdict, 'current'); // control
});

test('[RESISTE] solo ML-DSA-65 en el MCP: el registro (mintiendo valid:true, registered:true) sirve una clave ML-DSA-44 REAL o un tamaño de frontera → nunca current', async (t) => {
  const cases = [
    { alg: 'MlDsa44', pub: b64url(k44.publicKey) },
    { alg: 'MlDsa65', pub: b64url(k44.publicKey) },
    { alg: 'ML-DSA-44', pub: PUB },
    { alg: 'MlDsa65', pub: b64url(attackerKp.publicKey.subarray(0, 1951)) },
    { alg: 'MlDsa65', pub: b64url(new Uint8Array([...attackerKp.publicKey, 0])) },
    { alg: null, pub: PUB },
    { alg: 'MlDsa87', pub: PUB },
  ];
  for (const ck of cases) {
    const { d } = await verifyWith(t, basePassport({ registered: true, continuity: { ok: true }, current_key: { ...ck, kid: 'x' } }));
    assert.equal(d.ok, false, JSON.stringify(ck.alg));
    assert.notEqual(d.verdict, 'current');
  }
});

test('[RESISTE] pubkey_b64url del llamante ML-DSA-44 (1312 B) o firma 44 → signature_only falla; verifyManifestOffline exige 1952/3309', async (t) => {
  const m = forgedManifest();
  assert.equal(verifyManifestOffline(m, b64url(k44.publicKey)).ok, false);
  const sig44 = ml_dsa44.sign(new TextEncoder().encode(MANIFEST_SIGN_PREFIX + m.manifest_id), k44.secretKey);
  const m44 = { ...m, keys: { ...m.keys, signing: { alg: 'ML-DSA-44', kid: kidOf(k44.publicKey), pub: b64url(k44.publicKey) } }, signature: { alg: 'ML-DSA-44', kid: kidOf(k44.publicKey), sig: b64url(sig44) } };
  assert.equal(verifyManifestOffline(m44, b64url(k44.publicKey)).ok, false);
  const { d } = await verifyWith(t, basePassport(), { pubkey_b64url: b64url(k44.publicKey) });
  assert.equal(d.ok, false);
  assert.equal(d.signature_ok, false);
});

test('[RESISTE] list_agents: region mal formada nunca sale a la red (zod)', async (t) => {
  let calls = 0;
  const client = await bridge(t, async () => { calls++; return json({}, 404); });
  for (const region of ['co', 'CO\u0000', 'COL', ' CO', 'CО', '', 'CO&region=MX']) {
    const r = await client.callTool({ name: 'list_agents', arguments: { region } });
    assert.equal(r.isError, true, region);
  }
  assert.equal(calls, 0);
});
