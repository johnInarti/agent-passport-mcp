// REVISION ADVERSARIAL #2 Fase B.2 (2026-10-12). REAL ML-DSA-65.
// Run: npm run build && node --test test/registry-attacks-r2.mjs
// [HALLAZGO→ARREGLADO] = el test PASABA mientras el defecto existia; tras el fix cada assert esta INVERTIDO y pasa SOLO con el.
// [HALLAZGO · DEUDA]   = documentado sin arreglar (R2-4a/4b: seq/reloj entre replicas, deuda R2-4 del registro del servidor).
// [RESISTE]            = fija lo que aguanta.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { jcs, sha256Hex, b64url, kidOf, manifestId, registerRegistryTools, resetIndexFreshnessState, MANIFEST_SIGN_PREFIX, INDEX_SIGN_PREFIX } from '../dist/registry-tools.js';

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
const destroyedPassport = (m) => json({ agent_id: AGENT, agent_status: 'Destroyed', valid: false, current_key: { alg: 'MlDsa65', kid: m.keys.signing.kid, pub: PUB } });
const healthyPassport = (m) => json({ agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa65', kid: m.keys.signing.kid, pub: PUB } });

test('[HALLAZGO→ARREGLADO R2-7a] verify_agent_manifest con pubkey_b64url → verdict:"signature_only", ok:null (nunca true), sin isError si la firma verifica; firma rota → isError', async (t) => {
  const m = manifest();
  let passportFetched = false;
  const client = await bridge(t, async (url) => { if (/\/passport$/.test(String(url))) { passportFetched = true; return destroyedPassport(m); } return json({}, 404); });
  const r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m, pubkey_b64url: PUB } });
  const d = parse(r);
  assert.equal(r.isError, undefined);
  assert.equal(d.verdict, 'signature_only');   // campo maquina-legible: NO es el veredicto "current"
  assert.equal(d.ok, null);                     // ← antes: true (ambiguo con "todo vigente")
  assert.notEqual(d.ok, true);
  assert.equal(d.signature_ok, true);
  assert.equal(d.passport_valid, null);
  assert.equal(d.agent_active, null);
  assert.match(d.trust, /signature only/);
  assert.equal(passportFetched, false);         // con clave del llamador el registro no se consulta (y se dice)
  // firma rota con clave del llamador → isError, signature_ok false, verdict sigue siendo signature_only
  const broken = { ...m, signature: { ...m.signature, sig: b64url(new Uint8Array(3309)) } };
  const rb = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: broken, pubkey_b64url: PUB } });
  assert.equal(rb.isError, true);
  assert.equal(parse(rb).verdict, 'signature_only');
  assert.equal(parse(rb).signature_ok, false);
  // armonizado con #11 (follow-ups): un fallo PROBADO de la verificacion offline es ok:false, no null —
  // null queda reservado a "la firma verifica pero este camino nunca puede decir current"; nunca true
  assert.equal(parse(rb).ok, false);
  assert.notEqual(parse(rb).ok, true);
});

test('[RESISTE R2-7a] verify_agent_manifest registry-assisted: agente vigente → verdict:"current", ok:true; Destroyed → verdict:"not_current", ok:false, isError, razones', async (t) => {
  const m = manifest();
  let serve = healthyPassport;
  const client = await bridge(t, async (url) => (/\/passport$/.test(String(url)) ? serve(m) : json({}, 404)));
  const ok = parse(await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m } }));
  assert.equal(ok.verdict, 'current'); assert.equal(ok.ok, true);
  serve = destroyedPassport;
  const r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m } });
  assert.equal(r.isError, true);
  const d = parse(r);
  assert.equal(d.verdict, 'not_current'); assert.equal(d.ok, false); assert.equal(d.signature_ok, true);
  assert.deepEqual(d.not_ok_because, ['passport_valid=false (node verdict)', 'agent_active=false (status Destroyed)']);
});

test('[HALLAZGO→ARREGLADO R2-7b] get_agent_manifest de un agente DESTRUIDO con pasaporte invalido → ok:false, verdict:"not_current", isError y razones (alineado con #7)', async (t) => {
  const m = manifest();
  const client = await bridge(t, async (url) => {
    const u = String(url);
    if (/\/passport$/.test(u)) return destroyedPassport(m);
    if (u.endsWith(`/api/agents/registry/${AGENT}`)) return json({ manifest: m, verification: { key_status: 'revoked', agent_status: 'Destroyed', passport_valid: false, current: false } });
    return json({}, 404);
  });
  const r = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT } });
  const d = parse(r);
  assert.equal(r.isError, true);                // ← antes: undefined
  assert.equal(d.ok, false);                    // ← antes solo offline.ok:true, sin veredicto global
  assert.equal(d.verdict, 'not_current');
  assert.equal(d.signature_ok, true);           // la firma SI verifica (clave == actual): se dice por separado
  assert.equal(d.offline.ok, true);
  assert.equal(d.passport_valid, false);
  assert.equal(d.agent_active, false);
  assert.equal(d.agent_status, 'Destroyed');
  assert.deepEqual(d.not_ok_because, ['passport_valid=false (node verdict + registry local checks)', 'agent_active=false (status Destroyed)']);
  assert.equal(d.registry_verification.agent_status, 'Destroyed');
  assert.match(d.trust, /registry-assisted/);
});

test('[RESISTE R2-7b] get_agent_manifest de un agente VIGENTE → ok:true, verdict:"current", sin isError; registro caido (sin /passport) → ok:false con passport_valid/agent_active null', async (t) => {
  const m = manifest();
  let passportUp = true;
  const client = await bridge(t, async (url) => {
    const u = String(url);
    if (/\/passport$/.test(u)) return passportUp ? healthyPassport(m) : json({ error: 'node_unavailable' }, 503);
    if (u.endsWith(`/api/agents/registry/${AGENT}`)) return json({ manifest: m, verification: { key_status: 'current', agent_status: 'Active', passport_valid: true, current: true } });
    return json({}, 404);
  });
  const r = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT } });
  assert.equal(r.isError, undefined);
  const d = parse(r);
  assert.equal(d.ok, true); assert.equal(d.verdict, 'current'); assert.equal(d.signature_ok, true); assert.equal(d.passport_valid, true); assert.equal(d.agent_active, true);
  assert.equal('not_ok_because' in d, false);
  passportUp = false;
  const r2 = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT } });
  assert.equal(r2.isError, true);
  const d2 = parse(r2);
  assert.equal(d2.ok, false); assert.equal(d2.verdict, 'not_current'); assert.equal(d2.signature_ok, false); assert.equal(d2.passport_valid, null); assert.equal(d2.agent_active, null);
  assert.deepEqual(d2.not_ok_because, ['signature_ok=false', 'passport_valid=null (registry/node unavailable)', 'agent_active=null (registry/node unavailable)']);
});

test('[HALLAZGO R2-4a menor · DEUDA] dos replicas con reloj desfasado 10 s: el indice LEGITIMO de la replica atrasada se rechaza como index_rollback (flapping/DoS de disponibilidad)', async (t) => {
  const m = manifest();
  let serve = signIndex([entry(m)], NOW + 10, NOW - 100); // replica A, reloj adelantado
  const client = await bridge(t, async (url) => (/agents\.json$/.test(String(url)) ? json(serve) : json({}, 404)));
  assert.equal((await client.callTool({ name: 'list_agents', arguments: {} })).isError, undefined);
  serve = signIndex([entry(m)], NOW, NOW - 100);            // replica B: MISMO estado (mismo seq), reloj bien
  const r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, true);
  assert.equal(parse(r).error, 'index_rollback');
});

test('[HALLAZGO R2-4b menor · DEUDA] mismo seq e issued_at, contenido DISTINTO (agente presente / ausente): ambos firmados y ambos aceptados — seq no ordena estados', async (t) => {
  const m = manifest();
  const withAgent = signIndex([entry(m)], NOW, NOW - 100);
  const without = signIndex([], NOW, NOW - 100); // el agente fue destruido en el nodo: no hay fila nueva, seq NO cambia
  let serve = without;
  const client = await bridge(t, async (url) => (/agents\.json$/.test(String(url)) ? json(serve) : json({}, 404)));
  assert.equal(parse(await client.callTool({ name: 'list_agents', arguments: {} })).count, 0);
  serve = withAgent; // espejo sirve el otro, dentro de la ventana de 300 s
  const r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, undefined);
  assert.equal(parse(r).count, 1);
});
