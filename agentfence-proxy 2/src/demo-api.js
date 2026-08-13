'use strict';

const { InMemoryEvidenceLog } = require('./evidence');
const { buildProbes } = require('./prober');

/**
 * Everything under /demo/* is meant to be called directly from the
 * PUBLIC landing page's browser JS -- unauthenticated, from anonymous
 * visitors. That's a fundamentally different trust boundary than
 * /mcp (meant for an authenticated real agent client), so it gets its
 * own rules:
 *
 *   - CORS locked to an explicit origin allowlist (not '*'), since
 *     responses include policy/probe detail that shouldn't be
 *     fetchable cross-origin by an arbitrary third-party page
 *   - rate-limited per IP, since it's the one surface anyone on the
 *     internet can hit without credentials
 *   - every probe run uses a fresh InMemoryEvidenceLog: real, checkable
 *     hash-chained evidence is still returned in the response (that's
 *     the whole point of the demo), but it's discarded afterward and
 *     never touches the durable customer audit trail
 *
 * Mounted from HttpTransport for every request whose path starts with
 * "/demo/".
 */

const DEMO_SIGNING_SECRET = process.env.AGENTFENCE_DEMO_SIGNING_SECRET || 'demo-ephemeral-secret';

function clientKey(req) {
  // Render (and most PaaS) sit behind a proxy that sets this; fall back
  // to the socket address for local/direct testing.
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function applyCors(req, res, allowedOrigins) {
  const origin = req.headers.origin;
  if (!allowedOrigins) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readJsonBody(req, maxBytes = 64 * 1024) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error('body too large'), { statusCode: 413 });
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 });
  }
}

async function handleDemoRequest(req, res, url, { proxyServer, rateLimiter, allowedOrigins }) {
  applyCors(req, res, allowedOrigins);

  if (req.method === 'OPTIONS') {
    res.writeHead(204).end();
    return;
  }

  const rl = rateLimiter.check(clientKey(req));
  res.setHeader('X-RateLimit-Limit', String(rateLimiter.max));
  if (!rl.allowed) {
    res.setHeader('Retry-After', String(Math.ceil(rl.retryAfterMs / 1000)));
    sendJson(res, 429, { error: 'rate limit exceeded, try again shortly' });
    return;
  }
  res.setHeader('X-RateLimit-Remaining', String(rl.remaining));

  const route = `${req.method} ${url.pathname}`;

  if (route === 'GET /demo/health') {
    sendJson(res, 200, { status: 'ok' });
    return;
  }

  if (route === 'GET /demo/attacks') {
    const { liveToolsByServer, drift } = await proxyServer.getPermissionsSnapshot();
    const probes = buildProbes(proxyServer.policy, liveToolsByServer, drift);
    const attacks = probes
      .filter((p) => p.expectBlocked && !p.advisory && p.category !== 'control')
      .map((p) => ({ id: p.id, category: p.category, severity: p.severity, description: p.description }));
    sendJson(res, 200, { attacks });
    return;
  }

  if (route === 'GET /demo/probe') {
    const evidenceLog = new InMemoryEvidenceLog({ secret: DEMO_SIGNING_SECRET });
    const scorecard = await proxyServer.runProbeBattery({ evidenceLog });
    const verification = evidenceLog.verify();
    sendJson(res, 200, {
      ...scorecard,
      evidence: { recordCount: evidenceLog.records.length, chainVerified: verification.ok },
    });
    return;
  }

  if (route === 'POST /demo/try-attack') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      sendJson(res, err.statusCode || 400, { error: err.message });
      return;
    }
    if (!body.attackId || typeof body.attackId !== 'string') {
      sendJson(res, 400, { error: '"attackId" (string) is required -- see GET /demo/attacks for valid ids' });
      return;
    }
    const evidenceLog = new InMemoryEvidenceLog({ secret: DEMO_SIGNING_SECRET });
    const result = await proxyServer.runSingleProbe(body.attackId, { evidenceLog });
    if (!result) {
      sendJson(res, 404, { error: `unknown attackId "${body.attackId}"` });
      return;
    }
    const record = evidenceLog.records[evidenceLog.records.length - 1];
    sendJson(res, 200, {
      id: result.id,
      category: result.category,
      severity: result.severity,
      description: result.description,
      blocked: result.actualBlocked,
      decisionMessage: result.decisionMessage,
      evidence: { recordHash: record.recordHash, signature: record.signature, chainVerified: evidenceLog.verify().ok },
    });
    return;
  }

  sendJson(res, 404, { error: 'not found' });
}

module.exports = { handleDemoRequest };
