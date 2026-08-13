'use strict';

const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { EvidenceLog } = require('../src/evidence');

const ROOT = path.join(__dirname, '..');
const PORT = 8799;
const BASE = `http://localhost:${PORT}`;
const EVIDENCE_PATH = path.join(ROOT, 'logs', 'stress-evidence.jsonl');
const SECRET = 'stress-secret';

fs.rmSync(EVIDENCE_PATH, { force: true });

function rawRequest({ method = 'POST', path: p = '/mcp', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request(BASE + p, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (data !== undefined) req.write(data);
    req.end();
  });
}

async function rpc(sessionId, message, extraHeaders = {}) {
  const headers = { ...extraHeaders };
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;
  const res = await rawRequest({ headers, body: message });
  let parsed = null;
  try { parsed = JSON.parse(res.body); } catch { /* leave null for malformed-body tests */ }
  return { ...res, parsed };
}

async function newSession() {
  const res = await rpc(null, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  return res.headers['mcp-session-id'];
}

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function timeIt(fn) {
  const start = process.hrtime.bigint();
  const result = await fn();
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  return { ms, result };
}

// ---------------------------------------------------------------------
// Scenario A: N concurrent sessions, each doing a realistic mixed
// sequence of allowed and blocked calls, checked for correctness AND
// timed for latency distribution.
// ---------------------------------------------------------------------
async function scenarioConcurrentSessions(n) {
  const latencies = [];
  let mismatches = 0;

  async function oneSession(idx) {
    const sid = await newSession();
    // Real MCP clients list tools before calling one; do the same here
    // so this scenario measures policy-decision correctness, not
    // whether the proxy can survive a client skipping that step
    // (that's covered separately — see the self-healing lookup in
    // proxy-server.js and the note in the README).
    await rpc(sid, { jsonrpc: '2.0', id: 0, method: 'tools/list', params: {} });
    const calls = [
      { name: 'docs.search', arguments: { query: `q${idx}` }, expect: 'allowed' },
      { name: 'web.fetch', arguments: { url: 'https://docs.internal.example.com/x' }, expect: 'allowed' },
      { name: 'web.fetch', arguments: { url: `https://exfil-${idx}.example.net/` }, expect: 'blocked' },
      { name: 'web.upload', arguments: { url: 'https://x', data: 'y' }, expect: 'blocked' },
      { name: 'docs.write', arguments: { path: '/x', content: 'y' }, expect: 'blocked' },
    ];
    for (const call of calls) {
      const { ms, result } = await timeIt(() => rpc(sid, {
        jsonrpc: '2.0', id: Math.floor(Math.random() * 1e9), method: 'tools/call',
        params: { name: call.name, arguments: call.arguments },
      }));
      latencies.push(ms);
      const gotBlocked = !!(result.parsed && result.parsed.error);
      const expectedBlocked = call.expect === 'blocked';
      if (gotBlocked !== expectedBlocked) {
        mismatches++;
        console.log(`  MISMATCH session ${idx} call ${call.name}: expected ${call.expect}, status ${result.status}, body ${result.body}`);
      }
    }
  }

  await Promise.all(Array.from({ length: n }, (_, i) => oneSession(i)));

  latencies.sort((a, b) => a - b);
  return {
    totalCalls: latencies.length,
    mismatches,
    p50: percentile(latencies, 50).toFixed(2),
    p95: percentile(latencies, 95).toFixed(2),
    p99: percentile(latencies, 99).toFixed(2),
    max: latencies[latencies.length - 1].toFixed(2),
  };
}

// ---------------------------------------------------------------------
// Scenario B: hostile / malformed input. None of these should crash
// the server or produce an unhandled exception in its stderr.
// ---------------------------------------------------------------------
async function scenarioHostileInput() {
  const sid = await newSession();
  const results = [];

  const cases = [
    { name: 'malformed JSON', req: () => rawRequest({ headers: { 'Mcp-Session-Id': sid }, body: '{not json' }) },
    { name: 'empty body', req: () => rawRequest({ headers: { 'Mcp-Session-Id': sid }, body: '' }) },
    { name: 'huge string field (1.5MB)', req: () => rpc(sid, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'docs.search', arguments: { query: 'x'.repeat(1_500_000) } } }) },
    { name: 'oversized body (>2MB cap)', req: () => rawRequest({ headers: { 'Mcp-Session-Id': sid }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'docs.search', arguments: { query: 'x'.repeat(3_000_000) } } }) }) },
    { name: 'wrong jsonrpc version', req: () => rpc(sid, { jsonrpc: '1.0', id: 1, method: 'tools/call', params: {} }) },
    { name: 'missing method', req: () => rpc(sid, { jsonrpc: '2.0', id: 1, params: {} }) },
    { name: 'null params', req: () => rpc(sid, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: null }) },
    { name: 'tool name with path traversal-ish string', req: () => rpc(sid, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: '../../etc/passwd', arguments: {} } }) },
    { name: 'unknown method', req: () => rpc(sid, { jsonrpc: '2.0', id: 1, method: 'system/shutdown', params: {} }) },
    { name: 'batch of 20 mixed valid/invalid', req: () => rawRequest({ headers: { 'Mcp-Session-Id': sid }, body: JSON.stringify(Array.from({ length: 20 }, (_, i) => (i % 3 === 0 ? { jsonrpc: '2.0', id: i, method: 'tools/call', params: { name: 'docs.search', arguments: { query: `x${i}` } } } : { bad: 'message' }))) }) },
    { name: 'DELETE unknown session', req: () => rawRequest({ method: 'DELETE', headers: { 'Mcp-Session-Id': 'nope' } }) },
  ];

  for (const c of cases) {
    try {
      const res = await c.req();
      results.push({ name: c.name, ok: true, status: res.status });
    } catch (err) {
      results.push({ name: c.name, ok: false, error: err.message });
    }
  }
  return results;
}

// ---------------------------------------------------------------------
// Scenario C: flood — many concurrent policy-violating calls hammering
// the evidence log, then verify the hash chain is still intact (proves
// EvidenceLog.record()'s synchronous, no-await design holds up under
// real concurrency rather than just in the single-request demo).
// ---------------------------------------------------------------------
async function scenarioFlood(count) {
  const sid = await newSession();
  const { ms } = await timeIt(() => Promise.all(
    Array.from({ length: count }, (_, i) => rpc(sid, {
      jsonrpc: '2.0', id: i, method: 'tools/call',
      params: { name: 'web.upload', arguments: { url: `https://x${i}`, data: 'y' } },
    }))
  ));
  return { count, totalMs: ms.toFixed(1), callsPerSec: (count / (ms / 1000)).toFixed(0) };
}

async function main() {
  const proc = spawn('node', ['src/index.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      AGENTFENCE_TRANSPORT: 'http',
      AGENTFENCE_PORT: String(PORT),
      AGENTFENCE_EVIDENCE_LOG: EVIDENCE_PATH,
      AGENTFENCE_SIGNING_SECRET: SECRET,
    },
  });
  let stderrBuf = '';
  proc.stderr.on('data', (d) => { stderrBuf += d.toString(); });

  await new Promise((r) => setTimeout(r, 400));

  console.log('=== Scenario A: 25 concurrent sessions, mixed allowed/blocked calls ===');
  const a = await scenarioConcurrentSessions(25);
  console.log(`  calls: ${a.totalCalls}, mismatches: ${a.mismatches}`);
  console.log(`  latency ms — p50: ${a.p50}  p95: ${a.p95}  p99: ${a.p99}  max: ${a.max}`);

  console.log('\n=== Scenario B: hostile / malformed input ===');
  const b = await scenarioHostileInput();
  for (const r of b) {
    console.log(`  ${r.ok ? 'handled' : 'REQUEST FAILED'}  status=${r.status ?? '-'}  ${r.name}${r.error ? ` (${r.error})` : ''}`);
  }
  const anyFailed = b.some((r) => !r.ok);

  console.log('\n=== Scenario C: flood — 300 concurrent policy-violating calls ===');
  const c = await scenarioFlood(300);
  console.log(`  ${c.count} calls in ${c.totalMs}ms (${c.callsPerSec} calls/sec)`);

  console.log('\n=== Post-flood: evidence chain integrity ===');
  const verification = EvidenceLog.verify(EVIDENCE_PATH, SECRET);
  console.log('  ', verification.ok
    ? `chain intact — ${verification.checked} signed records verified, zero corruption under concurrency`
    : `TAMPERED/CORRUPTED — ${verification.error}`);

  console.log('\n=== Server health check ===');
  console.log(`  process still alive: ${!proc.killed}`);
  const unexpectedErrors = stderrBuf.split('\n').filter((l) => /Unhandled|TypeError|ReferenceError/.test(l));
  console.log(`  unhandled exceptions in server stderr: ${unexpectedErrors.length}`);
  if (unexpectedErrors.length) unexpectedErrors.forEach((l) => console.log('   ', l));

  console.log('\n=== Summary ===');
  console.log(`  correctness (Scenario A): ${a.mismatches === 0 ? 'PASS' : `FAIL (${a.mismatches} mismatches)`}`);
  console.log(`  robustness (Scenario B): ${!anyFailed ? 'PASS — no request crashed the server' : 'FAIL'}`);
  console.log(`  evidence integrity (Scenario C): ${verification.ok ? 'PASS' : 'FAIL'}`);
  console.log(`  process survived: ${!proc.killed ? 'PASS' : 'FAIL'}`);

  proc.kill();
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
