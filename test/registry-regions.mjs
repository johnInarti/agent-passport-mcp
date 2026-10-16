// Fractal Agent Commons MCP — regional index (`list_agents` with `region`, signed `scope` check) and the
// ONLY-ML-DSA-65 rule (a node/registry serving an ML-DSA-44 key is never "current"). node:test over the
// BUILT package (dist/), REAL ML-DSA-65 / ML-DSA-44.
// Run: npm run build && node --test test/registry-regions.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  jcs, sha256Hex, b64url, kidOf, manifestId, verifyIndexOffline, checkIndexScope, registerRegistryTools, resetIndexFreshnessState,
  MANIFEST_SIGN_PREFIX, INDEX_SIGN_PREFIX, REGION_RE,
} from '../dist/registry-tools.js';

const base = 'https://fractalai.net.co';
const AGENT = '0x' + '37'.repeat(32);
const agentKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x11));
const notaryKp = ml_dsa65.keygen(new Uint8Array(32).fill(0x33));
const k44 = ml_dsa44.keygen(new Uint8Array(32).fill(0x44));
const NOW = Math.floor(Date.now() / 1000);
const PUB = b64url(agentKp.publicKey);

function unsigned(kp, over = {}) {
  return {
    schema: 'fractalai-agent-manifest/1', version: 1, prev_manifest_id: null, issued_at: NOW, expires_at: NOW + 86400,
    agent: { id: AGENT, did: `did:web:fractalai.net.co:agents:${AGENT}`, name: 'MIDAS', owner: 'fractal1_pq_' + 'ab'.repeat(20), status: 'Active', passport_url: `${base}/api/agents/registry/${AGENT}/passport` },
    keys: { signing: { alg: 'ML-DSA-65', kid: kidOf(kp.publicKey), pub: b64url(kp.publicKey) }, receipts_directory: `${base}/.well-known/x402-receipt-keys`, jwks: `${base}/.well-known/jwks.json` },
    registry: { identity_root: '0x' + '27'.repeat(32), height: 1322415, signer_kid: '0'.repeat(16) },
    capabilities: [{ id: 'midas-attest', description: 'x', x402: { resource: `${base}/api/x402/midas-attest` }, sandbox: false }],
    operations: { intent_schema: 'commerce-intent/1', receipt: 'delivery-receipt v0.2.1', authorization: 'X-Agent-Authorization v2' },
    endpoints: { http: base, rpc: 'https://api.fractalai.net.co', mcp: '@fractalai/agent-passport-mcp', verify: '/api/passport/verify' },
    regions: [{ country: 'CO', currencies: ['COP', 'USD'], rails: ['usdc-base', 'wcop-base'] }],
    ...over,
  };
}
function sign(u, kp) {
  const id = manifestId(u);
  const sig = ml_dsa65.sign(new TextEncoder().encode(MANIFEST_SIGN_PREFIX + id), kp.secretKey);
  return { ...u, manifest_id: id, signature: { alg: 'ML-DSA-65', kid: kidOf(kp.publicKey), sig: b64url(sig) } };
}
const good = sign(unsigned(agentKp), agentKp);
const entry = { id: AGENT, name: 'MIDAS', did: `did:web:fractalai.net.co:agents:${AGENT}`, manifest_url: `${base}/api/agents/registry/${AGENT}`, manifest_id: good.manifest_id, version: 1, kid: good.keys.signing.kid, status: 'Active' };
/** `scope` goes INSIDE the signed canon, exactly as the registry server builds the index. */
function signIndex(agents, scope, { issued_at = NOW, seq = NOW, omitScope = false } = {}) {
  const idx = { schema: 'fractalai-agents-index/1', issued_at, expires_at: issued_at + 300, seq, registry: { identity_root: '0x' + '27'.repeat(32), height: 1, signer_kid: null }, ...(omitScope ? {} : { scope }), agents };
  const sig = ml_dsa65.sign(new TextEncoder().encode(INDEX_SIGN_PREFIX + sha256Hex(jcs(idx))), notaryKp.secretKey);
  return { ...idx, signature: { alg: 'ML-DSA-65', kid: kidOf(notaryKp.publicKey), sig: b64url(sig) } };
}
const PIN = { FRACTALAI_PINNED_RECEIPT_KEY: Buffer.from(notaryKp.publicKey).toString('base64') };

async function bridge(t, fetcher, env = PIN) {
  const originalFetch = globalThis.fetch;
  const originalEnv = { ...process.env };
  globalThis.fetch = fetcher;
  Object.assign(process.env, env);
  resetIndexFreshnessState();
  const server = new McpServer({ name: 'registry-regions-test', version: '0.0.0' });
  registerRegistryTools(server);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'buyer-test', version: '0.0.0' });
  await client.connect(ct);
  t.after(async () => { await client.close(); await server.close(); globalThis.fetch = originalFetch; process.env = originalEnv; });
  return client;
}
const parse = (r) => JSON.parse(r.content[0].text);
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
const regionOf = (url) => new URL(String(url)).searchParams.get('region');

test('checkIndexScope: regional needs scope.region == request; global needs scope absent or null; anything else is index_scope_mismatch', () => {
  assert.deepEqual(checkIndexScope({ scope: { region: 'CO' } }, 'CO'), { ok: true, scope: { region: 'CO' } });
  assert.equal(checkIndexScope({ scope: null }, 'CO').reason, 'index_scope_mismatch');
  assert.equal(checkIndexScope({}, 'CO').reason, 'index_scope_mismatch');
  assert.equal(checkIndexScope({ scope: { region: 'BR' } }, 'CO').reason, 'index_scope_mismatch');
  assert.equal(checkIndexScope({ scope: { region: 'CO', extra: 1 } }, 'CO').reason, 'index_scope_mismatch');
  assert.equal(checkIndexScope({ scope: 'CO' }, 'CO').reason, 'index_scope_mismatch');
  assert.deepEqual(checkIndexScope({ scope: null }, undefined), { ok: true, scope: null });
  assert.deepEqual(checkIndexScope({}, undefined), { ok: true, scope: null }); // pre-scope index
  assert.equal(checkIndexScope({ scope: { region: 'CO' } }, undefined).reason, 'index_scope_mismatch');
  assert.ok(REGION_RE.test('CO') && !REGION_RE.test('co') && !REGION_RE.test('COL'));
});

test('offline: the scope is inside the signed canon — editing it after signing breaks the index signature', () => {
  const pins = [Buffer.from(notaryKp.publicKey).toString('base64')];
  const co = signIndex([entry], { region: 'CO' });
  assert.equal(verifyIndexOffline(co, pins, { region: 'CO' }).ok, true);
  assert.equal(verifyIndexOffline({ ...co, scope: { region: 'BR' } }, pins, { region: 'CO' }).ok, false);
  assert.equal(verifyIndexOffline({ ...co, scope: { region: 'BR' } }, pins, { region: 'BR' }).ok, false);
  assert.equal(verifyIndexOffline({ ...co, scope: null }, pins, null).ok, false);
  const { scope: _s, ...stripped } = co; void _s;
  assert.equal(verifyIndexOffline(stripped, pins, null).ok, false);
  const global = signIndex([entry], null);
  assert.equal(verifyIndexOffline(global, pins, null).ok, true);
  assert.equal(verifyIndexOffline({ ...global, scope: { region: 'CO' } }, pins, { region: 'CO' }).ok, false);
  // R5-4: expectedScope is mandatory and an AUTHENTIC index of another scope is index_scope_mismatch (omission attack)
  assert.equal(verifyIndexOffline(co, pins, null).reason, 'index_scope_mismatch');
  assert.equal(verifyIndexOffline(co, pins, { region: 'MX' }).reason, 'index_scope_mismatch');
  assert.equal(verifyIndexOffline(global, pins, { region: 'CO' }).reason, 'index_scope_mismatch');
  assert.equal(verifyIndexOffline(co, pins).ok, false); // JS caller without expectedScope → fail closed
  assert.match(verifyIndexOffline(co, pins).reason, /expected_scope_required/);
  assert.equal(verifyIndexOffline(co, pins, { region: 'co' }).ok, false);
  const pre = signIndex([entry], null, { omitScope: true }); // pre-2026-10-12 index (no scope) is global
  assert.equal(verifyIndexOffline(pre, pins, null).ok, true);
  assert.equal(verifyIndexOffline(pre, pins, { region: 'CO' }).reason, 'index_scope_mismatch');
});

test('list_agents { region: CO } → fetches ?region=CO, verifies signature, requires scope.region == CO, returns scope; empty regional index is fine; include_all passes region through', async (t) => {
  const seen = [];
  const client = await bridge(t, async (url) => {
    const u = String(url); seen.push(u);
    if (/agents\.json/.test(u)) { const r = regionOf(u); return json(r === 'CO' ? signIndex([entry], { region: 'CO' }) : r === 'MX' ? signIndex([], { region: 'MX' }) : signIndex([entry], null)); }
    if (/\/api\/agents\/registry\?status=all/.test(u)) return json({ agents: [{ id: AGENT, current: true, regions: ['CO'] }] });
    return json({}, 404);
  });
  let d = parse(await client.callTool({ name: 'list_agents', arguments: { region: 'CO', include_all: true } }));
  assert.equal(d.index_signature_verified, true); assert.deepEqual(d.scope, { region: 'CO' }); assert.equal(d.count, 1); assert.equal(d.all_agents.length, 1);
  assert.ok(seen.some((u) => u.endsWith('/.well-known/agents.json?region=CO')));
  assert.ok(seen.some((u) => u.endsWith('/api/agents/registry?status=all&region=CO')));
  d = parse(await client.callTool({ name: 'list_agents', arguments: { region: 'MX' } }));
  assert.deepEqual([d.scope, d.count, d.agents], [{ region: 'MX' }, 0, []]);
  d = parse(await client.callTool({ name: 'list_agents', arguments: {} }));
  assert.equal(d.scope, null); assert.equal(d.count, 1);
  assert.ok(seen.some((u) => u.endsWith('/.well-known/agents.json')));
  // an ill-formed region never reaches the network (zod)
  const bad = await client.callTool({ name: 'list_agents', arguments: { region: 'co' } });
  assert.equal(bad.isError, true);
});

test('[ATTACK] global index re-served for a regional request (or regional for global / other region) → index_scope_mismatch, NO agents; forged scope → index_signature_invalid first', async (t) => {
  let serve = () => signIndex([entry], null);
  const client = await bridge(t, async (url) => (/agents\.json/.test(String(url)) ? json(serve(String(url))) : json({}, 404)));
  let r = await client.callTool({ name: 'list_agents', arguments: { region: 'CO' } });
  let d = parse(r);
  assert.equal(r.isError, true); assert.equal(d.error, 'index_scope_mismatch'); assert.equal(d.index_signature_verified, true); assert.equal(d.agents, undefined); assert.equal(d.requested_region, 'CO'); assert.equal(d.signed_scope, null);
  serve = () => signIndex([entry], { region: 'BR' });
  r = await client.callTool({ name: 'list_agents', arguments: { region: 'CO' } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'index_scope_mismatch'); assert.deepEqual(parse(r).signed_scope, { region: 'BR' });
  // pre-scope index (no scope key at all) is NOT acceptable for a regional request either
  serve = () => signIndex([entry], null, { omitScope: true });
  r = await client.callTool({ name: 'list_agents', arguments: { region: 'CO' } });
  assert.equal(parse(r).error, 'index_scope_mismatch');
  // ...but it is fine for a global request (backwards compatible)
  d = parse(await client.callTool({ name: 'list_agents', arguments: {} }));
  assert.equal(d.index_signature_verified, true); assert.equal(d.scope, null); assert.equal(d.count, 1);
  // regional index served for a GLOBAL request → mismatch too
  serve = () => signIndex([entry], { region: 'CO' });
  r = await client.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'index_scope_mismatch');
  // a genuinely signed global index whose scope is EDITED to CO after signing: the signature fails before any scope logic
  serve = () => ({ ...signIndex([entry], null), scope: { region: 'CO' } });
  r = await client.callTool({ name: 'list_agents', arguments: { region: 'CO' } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'index_signature_invalid'); assert.equal(parse(r).agents, undefined);
});

test('server 400 region_invalid is relayed as an error (no index, no fallback); anti-rollback is keyed PER scope', async (t) => {
  const client = await bridge(t, async (url) => {
    const u = String(url);
    if (!/agents\.json/.test(u)) return json({}, 404);
    const r = regionOf(u);
    if (r === 'ZZ') return json({ error: 'region_invalid', detail: 'region must be one assigned ISO 3166-1 alpha-2 code' }, 400);
    // the global index was built LATER than the regional one (server memo per region)
    if (r === 'CO') return json(signIndex([entry], { region: 'CO' }, { issued_at: NOW - 100, seq: NOW - 100 }));
    return json(signIndex([entry], null, { issued_at: NOW, seq: NOW }));
  });
  let r = await client.callTool({ name: 'list_agents', arguments: { region: 'ZZ' } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'region_invalid'); assert.equal(parse(r).agents, undefined);
  // global first (newer), then regional (older issued_at/seq): NOT a rollback, different scope
  assert.equal(parse(await client.callTool({ name: 'list_agents', arguments: {} })).index_signature_verified, true);
  const d = parse(await client.callTool({ name: 'list_agents', arguments: { region: 'CO' } }));
  assert.equal(d.index_signature_verified, true); assert.deepEqual(d.scope, { region: 'CO' });
});

test('ONLY ML-DSA-65: registry /passport reports a REAL ML-DSA-44 key (1312 B, alg MlDsa44, valid:false, reasons [key_algorithm_not_allowed]) → get_agent_manifest not_current with the reason; verify_agent_manifest → error key_algorithm_not_allowed', async (t) => {
  const pub44 = b64url(k44.publicKey);
  assert.equal(k44.publicKey.length, 1312);
  const passport44 = { agent_id: AGENT, registered: true, agent_status: 'Active', valid: false, reasons: ['key_algorithm_not_allowed'], current_key: { alg: 'MlDsa44', kid: null, pub: pub44, key_bytes: 1312, allowed: false } };
  const client = await bridge(t, async (url) => {
    const u = String(url);
    if (/\/passport$/.test(u)) return json(passport44);
    if (new RegExp(`/registry/${AGENT}$`).test(u)) return json({ manifest: good, verification: { key_status: 'rotated', agent_status: 'Active', passport_valid: false, current: false, reasons: ['key_algorithm_not_allowed', 'key_rotated'] } });
    return json({}, 404);
  });
  let r = await client.callTool({ name: 'get_agent_manifest', arguments: { agent_id: AGENT } });
  let d = parse(r);
  assert.equal(r.isError, true);
  assert.deepEqual([d.ok, d.verdict, d.signature_ok, d.passport_valid, d.agent_active], [false, 'not_current', false, false, true]);
  assert.ok(d.passport_reasons.includes('key_algorithm_not_allowed'));
  assert.match(d.offline.checks[0].detail, /key_algorithm_not_allowed/);
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } });
  d = parse(r);
  assert.equal(r.isError, true); assert.equal(d.ok, false); assert.equal(d.error, 'key_algorithm_not_allowed'); assert.equal(d.verdict, 'not_current'); assert.equal(d.current_alg, 'MlDsa44');
  assert.ok(d.passport_reasons.includes('key_algorithm_not_allowed'));
});

test('ONLY ML-DSA-65 is decided by the CLIENT too: a (hostile/old) registry saying valid:true for an MlDsa44-labelled key, or for a 1312-byte key labelled MlDsa65, is never current; a manifest embedding that 44 key is not verified under it', async (t) => {
  const pub44 = b64url(k44.publicKey);
  let passport = { agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa44', kid: kidOf(agentKp.publicKey), pub: PUB } };
  const client = await bridge(t, async (url) => (/\/passport$/.test(String(url)) ? json(passport) : json({}, 404)));
  let r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'key_algorithm_not_allowed'); assert.deepEqual(parse(r).passport_reasons, ['key_algorithm_not_allowed']);
  passport = { agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa65', kid: 'x', pub: pub44 } };
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: good } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'key_algorithm_not_allowed');
  // manifest "signed" with the 44 key, embedding the 44 key, node serving exactly that key → still not ok (nothing verified under a 44 key)
  const u44 = unsigned(agentKp, { keys: { ...unsigned(agentKp).keys, signing: { alg: 'ML-DSA-65', kid: kidOf(k44.publicKey), pub: pub44 } } });
  const id = manifestId(u44);
  const m44 = { ...u44, manifest_id: id, signature: { alg: 'ML-DSA-65', kid: kidOf(k44.publicKey), sig: b64url(ml_dsa44.sign(new TextEncoder().encode(MANIFEST_SIGN_PREFIX + id), k44.secretKey)) } };
  passport = { agent_id: AGENT, agent_status: 'Active', registered: true, valid: true, current_key: { alg: 'MlDsa44', kid: kidOf(k44.publicKey), pub: pub44 } };
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m44 } });
  assert.equal(r.isError, true); assert.equal(parse(r).error, 'key_algorithm_not_allowed');
  // and with a caller-supplied 44 key the offline path refuses by size, never inferring the algorithm
  r = await client.callTool({ name: 'verify_agent_manifest', arguments: { manifest: m44, pubkey_b64url: pub44 } });
  assert.equal(r.isError, true); assert.equal(parse(r).ok, false); assert.equal(parse(r).signature_ok, false);
});
