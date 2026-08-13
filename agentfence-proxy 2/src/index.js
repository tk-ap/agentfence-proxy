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
    const port = Number(process.env.AGENTFENCE_PORT || process.env.PORT || 8787);
    const allowedOrigins = process.env.AGENTFENCE_ALLOWED_ORIGINS
      ? process.env.AGENTFENCE_ALLOWED_ORIGINS.split(',').map((s) => s.trim())
      : null;
    const bearerToken = process.env.AGENTFENCE_BEARER_TOKEN || null;
    const demoAllowedOrigins = process.env.AGENTFENCE_DEMO_ALLOWED_ORIGINS
      ? process.env.AGENTFENCE_DEMO_ALLOWED_ORIGINS.split(',').map((s) => s.trim())
      : null; // null -> '*'; set this in production to lock the demo to the marketing site's origin
    const demoRateLimit = {
      windowMs: Number(process.env.AGENTFENCE_DEMO_RATE_WINDOW_MS || 60_000),
      max: Number(process.env.AGENTFENCE_DEMO_RATE_MAX || 20),
    };
    const http = new HttpTransport(proxyServer, { port, allowedOrigins, bearerToken, demoAllowedOrigins, demoRateLimit });
    await http.listen();
    process.stderr.write(`[agentfence] http proxy up on :${port} (/mcp + /demo/*), ${downstreams.size} downstream server(s), evidence -> ${evidencePath}\n`);
    if (!demoAllowedOrigins) {
      process.stderr.write(`[agentfence] WARNING: AGENTFENCE_DEMO_ALLOWED_ORIGINS not set — /demo/* is CORS-open to '*'. Set it to your site's origin before going live.\n`);
    }
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
