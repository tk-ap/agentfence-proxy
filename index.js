'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DownstreamClient } = require('./downstream-client');
const { ProxyServer } = require('./proxy-server');
const { HttpTransport } = require('./http-transport');
const { EvidenceLog } = require('./evidence');

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

async function main() {
  const configDir = process.env.AGENTFENCE_CONFIG_DIR || path.join(__dirname, '..', 'config');
  const serversConfig = loadJson(path.join(configDir, 'servers.json'));
  const policy = loadJson(path.join(configDir, 'policy.json'));

  const evidencePath = process.env.AGENTFENCE_EVIDENCE_LOG
    || path.join(__dirname, '..', 'logs', 'evidence.jsonl');
  const secret = process.env.AGENTFENCE_SIGNING_SECRET || 'dev-only-insecure-secret';
  const evidenceLog = new EvidenceLog(evidencePath, { secret });

  const downstreams = new Map();
  for (const [name, cfg] of Object.entries(serversConfig.servers)) {
    downstreams.set(name, new DownstreamClient(name, cfg));
  }

  const proxyServer = new ProxyServer({ downstreams, policy, evidenceLog });

  const transport = process.env.AGENTFENCE_TRANSPORT || 'stdio';

  if (transport === 'stdio') {
    proxyServer.attachStdio(process.stdin, process.stdout);
    process.stderr.write(`[agentfence] stdio proxy up, ${downstreams.size} downstream server(s), evidence -> ${evidencePath}\n`);
  } else if (transport === 'http') {
    const port = Number(process.env.AGENTFENCE_PORT || 8787);
    const allowedOrigins = process.env.AGENTFENCE_ALLOWED_ORIGINS
      ? process.env.AGENTFENCE_ALLOWED_ORIGINS.split(',').map((s) => s.trim())
      : null;
    const bearerToken = process.env.AGENTFENCE_BEARER_TOKEN || null;
    const http = new HttpTransport(proxyServer, { port, allowedOrigins, bearerToken });
    await http.listen();
    process.stderr.write(`[agentfence] http proxy up on :${port}/mcp, ${downstreams.size} downstream server(s), evidence -> ${evidencePath}\n`);
  } else {
    throw new Error(`unknown AGENTFENCE_TRANSPORT "${transport}" (expected "stdio" or "http")`);
  }

  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

main().catch((err) => {
  process.stderr.write(`[agentfence] fatal: ${err.stack}\n`);
  process.exit(1);
});
