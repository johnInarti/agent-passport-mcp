// Fractal Agent Commons MCP tools — node:test over the BUILT package (dist/), REAL ML-DSA-65.
// Run: npm run test:registry   (= npm run build && node --test test/registry-tools.mjs)
import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  jcs, sha256Hex, b64url, kidOf, manifestId, verifyManifestOffline, verifyIndexOffline, registerRegistryTools, unpinnedLocators,
  MANIFEST_SIGN_PREFIX, INDEX_SIGN_PREFIX, PINNED_LOCATORS,
} from '../dist/registry-tools.js';

const base = 'https://fractalai.net.co';
const AGENT = '0x' + '37'.repeat(32);
const agentKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x11));
const otherKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x22));
const notaryKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x33));
const NOW = Math.floor(Date.now() / 1000);

function unsigned(kp, over = {}) {
  const pub = b64url(kp.publicKey);
  return {
    schema: 'fractalai-agent-manifest/1', version: 1, prev_manifest_id: null, issued_at: NOW, expires_at: NOW + 86400,
    agent: { id: AGENT, did: `did:web:fractalai.net.co:agents:${AGENT}`, name: 'MIDAS', owner: 'fractal1_pq_' + 'ab'.repeat(20), status: 'Active', passport_url: `${base}/api/agents/registry/${AGENT}/passport` },
    keys: { signing: { alg: 'ML-DSA-65', kid: kidOf(kp.publicKey), pub }, receipts_directory: `${base}/.well-known/x402-receipt-keys`, jwks: `${base}/.well-known/jwks.json` },
    registry: { identity_root: '0x' + '27'.repeat(32), height: 1322415, signer_kid: '0'.repeat(16) },
    capabilities: [{ id: 'midas-attest', description: 'x', x402: { resource: `${base}/api/x402/midas-attest`, accepts_hint: 'USDC/eip155:8453' }, sandbox: false }],
    operations: { intent_schema: 'commerce-intent/1', receipt: 'delivery-receipt v0.2.1', authorization: 'X-Agent-Authorization v2' },
    endpoints: { http: base, rpc: 'https://api.fractalai.net.co', mcp: '@fractalai/agent-passport-mcp', verify: '/api/passport/verify' },
    ...over,
  };
}
function sign(u, kp) {
  const id = manifestId(u);
  const sig = ml_dsa65.sign(new TextEncoder().encode(MANIFEST_SIGN_PREFIX + id), kp.secretKey);
  return { ...u, manifest_id: id, signature: { alg: 'ML-DSA-65', kid: kidOf(kp.publicKey), sig: b64url(sig) } };
}
function signIndex(agents, kp, issued_at = NOW, seq = NOW) {
  const idx = { schema: 'fractalai-agents-index/1', issued_at, expires_at: issued_at + 300, seq, registry: { identity_root: '0x' + '27'.repeat(32), height: 1, signer_kid: null }, agents };
  const sig = ml_dsa65.sign(new TextEncoder().encode(INDEX_SIGN_PREFIX + sha256Hex(jcs(idx))), kp.secretKey);
  return { ...idx, signature: { alg: 'ML-DSA-65', kid: kidOf(kp.publicKey), sig: b64url(sig) } };
}
const PUB = b64url(agentKp.publicKey);
const good = sign(unsigned(agentKp), agentKp);

test('JCS is order-independent and manifest_id excludes signature + manifest_id', () => {
  assert.equal(jcs({ b: 1, a: [true, null, 'x'] }), '{"a":[true,null,"x"],"b":1}');
  const reordered = Object.fromEntries(Object.entries(good).reverse());
  assert.equal(manifestId(reordered), good.manifest_id);
  assert.equal(manifestId({ ...good, signature: { alg: 'none' }, manifest_id: 'zz' }), good.manifest_id);
  assert.equal(good.manifest_id.length, 64);
});

test('offline manifest verification: real ML-DSA-65 passes; forged/tampered/alg-confused fail', () => {
  assert.equal(verifyManifestOffline(good, PUB).ok, true);
  // signed by another key but claiming the agent's key
  const forged = { ...sign(unsigned(agentKp), otherKp), signature: { ...sign(unsigned(agentKp), otherKp).signature, kid: kidOf(agentKp.publicKey) } };
  const f = verifyManifestOffline(forged, PUB);
  assert.equal(f.ok, false);
  assert.ok(f.checks.some((c) => /verifies OFFLINE/.test(c.name) && c.pass === false));
  // body edited after signing → manifest_id mismatch
  assert.equal(verifyManifestOffline({ ...good, agent: { ...good.agent, name: 'EVIL' } }, PUB).ok, false);
  // signature byte flipped
  const sigBytes = Buffer.from(good.signature.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); sigBytes[9] ^= 1;
  assert.equal(verifyManifestOffline({ ...good, signature: { ...good.signature, sig: b64url(sigBytes) } }, PUB).ok, false);
  // alg confusion fails BEFORE crypto
  const a44 = verifyManifestOffline({ ...good, signature: { ...good.signature, alg: 'ML-DSA-44' } }, PUB);
  assert.equal(a44.ok, false);
  assert.equal(a44.checks.length, 2);
  // wrong verifier key (another agent's) → kid mismatch, never "attacker == attacker"
  assert.equal(verifyManifestOffline(good, b64url(otherKp.publicKey)).ok, false);
  // 1312-byte key (ML-DSA-44 size) rejected by size, never inferred
  assert.equal(verifyManifestOffline(good, b64url(new Uint8Array(1312))).ok, false);
});

test('offline index verification against pinned notary keys; altered index or unpinned signer fail', () => {
  const pins = [Buffer.from(notaryKp.publicKey).toString('base64')];
  const idx = signIndex([{ id: AGENT, name: 'MIDAS', did: `did:web:fractalai.net.co:agents:${AGENT}`, manifest_url: `${base}/api/agents/registry/${AGENT}`, manifest_id: good.manifest_id, version: 1, kid: good.keys.signing.kid, status: 'Active' }], notaryKp);
  assert.equal(verifyIndexOffline(idx, pins, null).ok, true);
  assert.equal(verifyIndexOffline({ ...idx, agents: [] }, pins, null).ok, false);
  assert.equal(verifyIndexOffline({ ...idx, issued_at: NOW + 1 }, pins, null).ok, false);
  assert.equal(verifyIndexOffline(signIndex([], otherKp), pins, null).ok, false);
  assert.match(verifyIndexOffline(signIndex([], otherKp), pins, null).reason, /none of the pinned/);
  const s = Buffer.from(idx.signature.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); s[3] ^= 1;
  assert.equal(verifyIndexOffline({ ...idx, signature: { ...idx.signature, sig: b64url(s) } }, pins, null).ok, false);
  assert.equal(verifyIndexOffline({ ...idx, signature: { ...idx.signature, alg: 'ML-DSA-44' } }, pins, null).ok, false);
});

test('#11 offline: agent-declared locators must be the official FractalAI ones; a genuinely signed manifest with a foreign jwks/rpc/verify is not ok', () => {
  assert.deepEqual(PINNED_LOCATORS, {
    receipts_directory: 'https://fractalai.net.co/.well-known/x402-receipt-keys', jwks: 'https://fractalai.net.co/.well-known/jwks.json',
    http: 'https://fractalai.net.co', rpc: 'https://api.fractalai.net.co', verify: ['/api/passport/verify', 'https://fractalai.net.co/api/passport/verify'],
  });
  assert.deepEqual(unpinnedLocators(good), []);
  assert.deepEqual(unpinnedLocators({}), ['keys.receipts_directory', 'keys.jwks', 'endpoints.http', 'endpoints.rpc', 'endpoints.verify']);
  const okAbs = sign(unsigned(agentKp, { endpoints: { ...unsigned(agentKp).endpoints, verify: `${base}/api/passport/verify` } }), agentKp);
  assert.equal(verifyManifestOffline(okAbs, PUB).ok, true);
  const evil = sign(unsigned(agentKp, {
    keys: { ...unsigned(agentKp).keys, jwks: 'https://fractalai.net.co.evil.example/.well-known/jwks.json' },
    endpoints: { ...unsigned(agentKp).endpoints, rpc: 'https://evil.example', verify: 'https://evil.example/api/passport/verify' },
  }), agentKp);
  const r = verifyManifestOffline(evil, PUB);
  assert.equal(r.ok, false);
  assert.equal(r.checks.find((c) => /verifies OFFLINE/.test(c.name)).pass, true); // the signature is real
  const pin = r.checks.find((c) => /official FractalAI locators/.test(c.name));
  assert.equal(pin.pass, false);
  assert.equal(pin.detail, 'not pinned: keys.jwks, endpoints.rpc, endpoints.verify');
});

async function bridge(t, fetcher, env = {}) {
  const originalFetch = globalThis.fetch;
  const originalEnv = { ...process.env };
  globalThis.fetch = fetcher;
  Object.assign(process.env, env);
  const server = new McpServer({ name: 'registry-test', version: '0.0.0' });
  const names = registerRegistryTools(server);
  assert.deepEqual(names, ['list_agents', 'get_agent_manifest', 'verify_agent_manifest']);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'buyer-test', version: '0.0.0' });
  await client.connect(ct);
  t.after(async () => { await client.close(); await server.close(); globalThis.fetch = originalFetch; process.env = originalEnv; });
  return client;
}
const parse = (r) => JSON.parse(r.content[0].text);
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

test('verify_agent_manifest over MCP: caller key → offline ok; registry current key ≠ embedded → key_not_current; forged → fails', async (t) => {
  let currentPub = PUB;
  const client = await bridge(t, async (url) => {
    if (/\/passport$/.test(String(url))) return json({ agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa65', kid: kidOf(Buffer.from(currentPub.replace(/-/g, '+').replace(/_/g, '/'), 'base64')), pub: currentPub } });
    return json({ error: 'nope' }, 404);
  });
  let r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good, pubkey_b64url: PUB } });
  // R2-7a (revision 2): con clave del llamador el veredicto es signature_only — ok es null (nunca true), signature_ok true
  assert.equal(r.isError, undefined); assert.equal(parse(r).ok, null); assert.equal(parse(r).verdict, 'signature_only'); assert.equal(parse(r).signature_ok, true); assert.match(parse(r).trust, /caller-supplied/);
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } });
  assert.equal(parse(r).ok, true); assert.match(parse(r).trust, /registry-assisted/);
  // rotation: the registry/node now reports another current key → the embedded key is NOT used
  currentPub = b64url(otherKp.publicKey);
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'key_not_current');
  // forged with the attacker's own key AND attacker's key reported... still only passes if the registry says so (it does not here)
  const attackerManifest = sign(unsigned(otherKp), otherKp);
  currentPub = PUB;
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: attackerManifest } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'key_not_current');
});

test('list_agents over MCP verifies the index signature against the PINNED key (env override) and flags an unpinned signer', async (t) => {
  const idx = signIndex([{ id: AGENT, name: 'MIDAS', did: `did:web:fractalai.net.co:agents:${AGENT}`, manifest_url: `${base}/api/agents/registry/${AGENT}`, manifest_id: good.manifest_id, version: 1, kid: good.keys.signing.kid, status: 'Active' }], notaryKp);
  const client = await bridge(t, async (url) => {
    if (/agents\.json$/.test(String(url))) return json(idx);
    if (/registry\?status=all$/.test(String(url))) return json({ agents: [{ id: AGENT, current: false, reasons: ['key_rotated'] }] });
    return json({}, 404);
  }, { FRACTALAI_PINNED_RECEIPT_KEY: Buffer.from(notaryKp.publicKey).toString('base64') });
  let r = await client.callTool({ name: 'list_agents', arguments: { include_all: true } });
  let d = parse(r);
  assert.equal(d.index_signature_verified, true); assert.equal(d.signer_kid, kidOf(notaryKp.publicKey)); assert.equal(d.count, 1); assert.equal(d.all_agents.length, 1);
  // same index, but the operator pins a DIFFERENT key → ERROR, no agents (never trusts the server's signer claim)
  process.env.FRACTALAI_PINNED_RECEIPT_KEY = Buffer.from(otherKp.publicKey).toString('base64');
  r = await client.callTool({ name: 'list_agents', arguments: {} });
  d = parse(r);
  assert.equal(r.isError, true);
  assert.equal(d.index_signature_verified, false); assert.equal(d.error, 'index_signature_invalid'); assert.match(d.detail, /none of the pinned/);
  assert.equal(d.agents, undefined);
});

test('verify_agent_manifest over MCP: ok only when signature_ok && passport_valid && agent_active; each verdict reported separately', async (t) => {
  let passport = { agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa65', kid: good.keys.signing.kid, pub: PUB } };
  const client = await bridge(t, async (url) => (/\/passport$/.test(String(url)) ? json(passport) : json({}, 404)));
  let d = parse(await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } }));
  assert.deepEqual([d.ok, d.signature_ok, d.passport_valid, d.agent_active], [true, true, true, true]);
  passport = { ...passport, agent_status: 'Paused' };
  let r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } });
  d = parse(r);
  assert.equal(r.isError, true);
  assert.deepEqual([d.ok, d.signature_ok, d.passport_valid, d.agent_active], [false, true, true, false]);
  passport = { ...passport, agent_status: 'Active', valid: false };
  d = parse(await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } }));
  assert.deepEqual([d.ok, d.signature_ok, d.passport_valid, d.agent_active], [false, true, false, true]);
  // caller-supplied key: signature only, on-chain verdicts explicitly null
  d = parse(await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good, pubkey_b64url: PUB } }));
  assert.deepEqual([d.ok, d.verdict, d.signature_ok, d.passport_valid, d.agent_active], [null, 'signature_only', true, null, null]); // R2-7a: ok nunca true en signature_only
});

test('R3-2 (coherencia MCP): el registro aplica continuidad en /passport → valid:false + reasons[passport_binding_mismatch] se refleja como not_current con passport_reasons (nunca "current" para la identidad de otro bajo este agent_id)', async (t) => {
  // El RPC hostil sirve la identidad del atacante (clave actual = la del manifest firmado por el) para ESTE agent_id; el
  // registro responde valid:false por continuidad con la canonical congelada. Antes (R3-2) devolvia valid:true.
  const passport = { agent_id: AGENT, registered: true, agent_status: 'Active', valid: false, reasons: ['passport_binding_mismatch'], current_key: { alg: 'MlDsa65', kid: good.keys.signing.kid, pub: PUB } };
  const client = await bridge(t, async (url) => {
    const u = String(url);
    if (/\/passport$/.test(u)) return json(passport);
    if (new RegExp(`/registry/${AGENT}$`).test(u)) return json({ manifest: good, verification: { key_status: 'current', agent_status: 'Active', passport_valid: false, current: false, reasons: ['passport_binding_mismatch'] } });
    return json({}, 404);
  });
  let r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } });
  let d = parse(r);
  assert.equal(r.isError, true);
  assert.deepEqual([d.ok, d.verdict, d.signature_ok, d.passport_valid, d.agent_active], [false, 'not_current', true, false, true]);
  assert.deepEqual(d.not_ok_because, ['passport_valid=false (node verdict)']);
  assert.deepEqual(d.passport_reasons, ['passport_binding_mismatch']);
  r = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT } });
  d = parse(r);
  assert.equal(r.isError, true);
  assert.deepEqual([d.ok, d.verdict, d.passport_valid], [false, 'not_current', false]);
  assert.deepEqual(d.passport_reasons, ['passport_binding_mismatch']);
  // sin reasons (registro antiguo) el campo no aparece; valid:true → sin passport_reasons
  passport.valid = true; delete passport.reasons;
  d = parse(await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } }));
  assert.equal(d.ok, true); assert.equal(d.passport_reasons, undefined);
});

test('get_agent_manifest over MCP: fetches, re-derives manifest_id and verifies only with the current key', async (t) => {
  const client = await bridge(t, async (url) => {
    const u = String(url);
    if (/\/passport$/.test(u)) return json({ agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa65', kid: good.keys.signing.kid, pub: PUB } });
    if (/\/v\/1$/.test(u) || new RegExp(`/registry/${AGENT}$`).test(u)) return json({ manifest: good, verification: { key_status: 'current', agent_status: 'Active', passport_valid: true } });
    return json({ error: 'version_not_found' }, 404);
  });
  let d = parse(await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT } }));
  assert.equal(d.offline.ok, true); assert.equal(d.manifest_id, good.manifest_id); assert.equal(d.registry_verification.key_status, 'current');
  d = parse(await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT, version: 1 } }));
  assert.equal(d.offline.ok, true);
  const r = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT, version: 9 } });
  assert.equal(r.isError, true);
  const bad = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: 'not-an-id' } });
  assert.equal(bad.isError, true);
});
