'use strict';

// This is the "gate and prove" piece of the pitch made literal: a CI
// step that fires the adversarial probe battery at the current policy
// and fails the build if containment isn't 100%, or if the evidence
// chain doesn't verify. Meant to run in PR checks so a policy change
// that opens a hole gets caught before merge, not after an incident.

const path = require('node:path');
const fs = require('node:fs');
const { DownstreamClient } = require('../src/downstream-client');
const { ProxyServer } = require('../src/proxy-server');
const { EvidenceLog } = require('../src/evidence');

const ROOT = path.join(__dirname, '..');
const EVIDENCE_PATH = path.join(ROOT, 'logs', 'ci-probe-evidence.jsonl');
const SECRET = process.env.AGENTFENCE_SIGNING_SECRET || 'ci-secret';

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

async function main() {
  fs.rmSync(EVIDENCE_PATH, { force: true });

  const configDir = process.env.AGENTFENCE_CONFIG_DIR || path.join(ROOT, 'config');
  const serversConfig = loadJson(path.join(configDir, 'servers.json'));
  const policy = loadJson(path.join(configDir, 'policy.json'));
  const evidenceLog = new EvidenceLog(EVIDENCE_PATH, { secret: SECRET });

  const downstreams = new Map();
  for (const [name, cfg] of Object.entries(serversConfig.servers)) {
    downstreams.set(name, new DownstreamClient(name, cfg));
  }

  const proxyServer = new ProxyServer({ downstreams, policy, evidenceLog });

  const response = await proxyServer.handleMessage({
    jsonrpc: '2.0', id: 'ci-gate', method: 'agentfence/probe', params: {},
  });
  const scorecard = response.result;

  console.log(`\nContainment score: ${scorecard.containmentScore}% (${scorecard.caught}/${scorecard.attackProbes} attack probes caught)`);
  console.log(`Control probes (must all pass through): ${scorecard.controlProbes}, false positives: ${scorecard.falsePositives.length}`);

  if (scorecard.missed.length > 0) {
    console.log(`\n❌ MISSED — the following attacks were NOT blocked:`);
    for (const m of scorecard.missed) {
      console.log(`   [${m.severity}] ${m.id}: ${m.description}`);
    }
  }
  if (scorecard.falsePositives.length > 0) {
    console.log(`\n⚠️  FALSE POSITIVES — legitimate calls were incorrectly blocked:`);
    for (const fp of scorecard.falsePositives) {
      console.log(`   ${fp.id}: ${fp.description}`);
    }
  }
  if (scorecard.advisories.length > 0) {
    console.log(`\nℹ️  Advisories (not build-blocking, review policy intent):`);
    for (const a of scorecard.advisories) {
      console.log(`   ${a.id}: ${a.description} (currently ${a.actualBlocked ? 'blocked' : 'ALLOWED'})`);
    }
  }

  const verification = EvidenceLog.verify(EVIDENCE_PATH, SECRET);
  console.log(`\nEvidence chain: ${verification.ok ? `intact (${verification.checked} records)` : `BROKEN — ${verification.error}`}`);

  for (const client of downstreams.values()) client.close();

  const pass = scorecard.missed.length === 0 && scorecard.falsePositives.length === 0 && verification.ok;
  console.log(`\n${pass ? '✅ GATE PASSED' : '❌ GATE FAILED'}`);
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error('probe-ci-check crashed:', err);
  process.exit(1);
});
