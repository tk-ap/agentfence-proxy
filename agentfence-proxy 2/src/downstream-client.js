'use strict';

const { spawn } = require('node:child_process');
const { attachReader, writeMessage, newId } = require('./jsonrpc');

/**
 * DownstreamClient owns one child process running a real (or mock) MCP
 * tool server, speaks JSON-RPC to it over stdio, and exposes a simple
 * request() promise API. This is deliberately dependency-free so the
 * scaffold runs today without `npm install`; swapping in the official
 * @modelcontextprotocol/sdk client transport later is a drop-in change
 * behind this same interface.
 */
class DownstreamClient {
  constructor(name, { command, args = [], env = {} }) {
    this.name = name;
    this.pending = new Map(); // id -> {resolve, reject}
    this.child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    });

    this.child.stderr.on('data', (chunk) => {
      process.stderr.write(`[downstream:${name}] ${chunk}`);
    });

    attachReader(this.child.stdout, (msg) => this._handleMessage(msg));

    this.child.on('exit', (code) => {
      process.stderr.write(`[downstream:${name}] exited with code ${code}\n`);
      for (const { reject } of this.pending.values()) {
        reject(new Error(`downstream "${name}" exited before responding`));
      }
      this.pending.clear();
    });
  }

  _handleMessage(msg) {
    if (msg.id !== undefined && this.pending.has(msg.id)) {
      const { resolve, reject } = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message || 'downstream error'));
      else resolve(msg.result);
    }
    // Notifications from the downstream server (no id) are not forwarded
    // in this scaffold — a real proxy would selectively relay these.
  }

  request(method, params, { timeoutMs = 5000 } = {}) {
    const id = newId();
    const message = { jsonrpc: '2.0', id, method, params };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`downstream "${this.name}" timed out on ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (r) => { clearTimeout(timer); resolve(r); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      writeMessage(this.child.stdin, message);
    });
  }

  close() {
    this.child.kill();
  }
}

module.exports = { DownstreamClient };
