'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { handleDemoRequest } = require('./demo-api');
const { RateLimiter } = require('./rate-limiter');

const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2MB — generous for tool-call payloads, small enough to bound abuse

/**
 * Streamable HTTP transport per MCP spec 2025-03-26 (the transport that
 * superseded the old dual-endpoint HTTP+SSE design). A single endpoint
 * (`/mcp`) accepts POST (send a message, get a response) and GET
 * (server push via SSE — not implemented here, see README).
 *
 * This is what lets AgentFence front a HOSTED agent rather than only a
 * local subprocess: the agent's MCP client talks HTTP to this instead
 * of spawning a local proxy process.
 *
 * Also mounts /demo/* — a separate, public, rate-limited, CORS-locked
 * surface (see demo-api.js) for the marketing site's live-demo widget.
 * /mcp and /demo/* are deliberately different trust boundaries: /mcp
 * assumes an authenticated real agent client and applies no CORS by
 * default; /demo/* assumes anonymous browser traffic and applies both
 * CORS and per-IP rate limiting.
 *
 * Deliberately included even though it's easy to skip in a scaffold:
 *   - Origin validation (mitigates DNS-rebinding attacks against local
 *     or intranet-bound proxies — a real MCP security requirement, not
 *     decoration)
 *   - Session management via Mcp-Session-Id
 *   - A body size cap, since an agent-facing HTTP endpoint is an
 *     attacker-facing HTTP endpoint the moment anything upstream of the
 *     agent is compromised
 */
class HttpTransport {
  constructor(proxyServer, {
    port = 8787,
    allowedOrigins = null, // null = no Origin header required/checked (fine for non-browser clients); array = allowlist
    bearerToken = null, // null = no auth required (dev only)
    demoAllowedOrigins = null, // null = '*' (fine for read-only, non-sensitive demo data); array = allowlist
    demoRateLimit = { windowMs: 60_000, max: 20 },
  } = {}) {
    this.proxyServer = proxyServer;
    this.port = port;
    this.allowedOrigins = allowedOrigins;
    this.bearerToken = bearerToken;
    this.demoAllowedOrigins = demoAllowedOrigins;
    this.sessions = new Map(); // sessionId -> { createdAt }
    this.rateLimiter = new RateLimiter(demoRateLimit);
    this._sweepInterval = setInterval(() => this.rateLimiter.sweep(), 5 * 60_000).unref();
    this.server = http.createServer((req, res) => this._handleRequest(req, res));
  }

  listen() {
    return new Promise((resolve) => this.server.listen(this.port, () => resolve(this)));
  }

  close() {
    clearInterval(this._sweepInterval);
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  _checkOrigin(req) {
    if (!this.allowedOrigins) return true;
    const origin = req.headers.origin;
    if (!origin) return true; // non-browser clients typically send no Origin
    return this.allowedOrigins.includes(origin);
  }

  _checkAuth(req) {
    if (!this.bearerToken) return true;
    const header = req.headers.authorization || '';
    return header === `Bearer ${this.bearerToken}`;
  }

  _readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      let oversize = false;
      const chunks = [];
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          // Stop retaining data once we're over the cap (bounds memory),
          // but let the request finish draining naturally instead of
          // destroying the socket mid-stream — destroying it here races
          // with the client still writing and surfaces as an ECONNRESET
          // on their end instead of the clean 413 we intend to send.
          oversize = true;
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        if (oversize) reject(Object.assign(new Error('payload too large'), { statusCode: 413 }));
        else resolve(Buffer.concat(chunks).toString('utf8'));
      });
      req.on('error', reject);
    });
  }

  async _handleRequest(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.pathname === '/' || url.pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ status: 'ok', service: 'agentfence-proxy' }));
      return;
    }

    if (url.pathname.startsWith('/demo/')) {
      try {
        await handleDemoRequest(req, res, url, {
          proxyServer: this.proxyServer,
          rateLimiter: this.rateLimiter,
          allowedOrigins: this.demoAllowedOrigins,
        });
      } catch (err) {
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: err.message }));
        }
      }
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404).end();
      return;
    }

    if (!this._checkOrigin(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'origin not allowed' }));
      return;
    }
    if (!this._checkAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }

    if (req.method === 'POST') return this._handlePost(req, res);
    if (req.method === 'GET') {
      // Spec-compliant fallback: we don't offer server-initiated push on
      // this endpoint (no server-to-client notifications exist in this
      // proxy today), so per spec we respond 405 rather than pretending
      // to support a stream we'd never write to.
      res.writeHead(405, { Allow: 'POST' }).end();
      return;
    }
    if (req.method === 'DELETE') {
      const sid = req.headers['mcp-session-id'];
      if (sid) this.sessions.delete(sid);
      res.writeHead(204).end();
      return;
    }

    res.writeHead(405, { Allow: 'POST, GET, DELETE' }).end();
  }

  async _handlePost(req, res) {
    let bodyText;
    try {
      bodyText = await this._readBody(req);
    } catch (err) {
      res.writeHead(err.statusCode || 400, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ error: err.message }));
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'invalid JSON' } }));
      return;
    }

    const messages = Array.isArray(parsed) ? parsed : [parsed];
    if (messages.length === 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ error: 'empty batch' }));
      return;
    }

    const isInitialize = messages.some((m) => m && m.method === 'initialize');
    let sessionId = req.headers['mcp-session-id'];

    if (isInitialize) {
      sessionId = crypto.randomUUID();
      this.sessions.set(sessionId, { createdAt: Date.now() });
    } else if (this.sessions.size > 0) {
      // Only enforce session presence once at least one session exists —
      // keeps the stateless single-shot case (no prior initialize) usable
      // for simple scripts/tests, while real multi-turn clients get real
      // session isolation once a session has been established.
      if (!sessionId || !this.sessions.has(sessionId)) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
          .end(JSON.stringify({ error: 'missing or unknown Mcp-Session-Id' }));
        return;
      }
    }

    const responses = [];
    for (const msg of messages) {
      let response;
      try {
        response = await this.proxyServer.handleMessage(msg);
      } catch (err) {
        response = { jsonrpc: '2.0', id: msg && msg.id, error: { code: -32000, message: err.message } };
      }
      if (response) responses.push(response);
    }

    const headers = { 'Content-Type': 'application/json' };
    if (sessionId) headers['Mcp-Session-Id'] = sessionId;

    if (responses.length === 0) {
      // All messages were notifications — spec says respond 202 with no body.
      res.writeHead(202, headers).end();
      return;
    }

    const payload = Array.isArray(parsed) ? responses : responses[0];

    const accept = req.headers.accept || '';
    if (accept.includes('text/event-stream') && !accept.includes('application/json')) {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
      res.end();
      return;
    }

    res.writeHead(200, headers).end(JSON.stringify(payload));
  }
}

module.exports = { HttpTransport };
