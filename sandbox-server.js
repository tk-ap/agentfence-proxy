'use strict';
// Mock downstream server exposing a declared, path-constrained write
// tool. Unlike docs.write (deliberately undeclared, to demo excess-
// permission detection), sandbox.write IS declared with a
// path-prefix-allowlist rule -- so the probe engine has a real
// constrained tool to attack, not just an undeclared one.

const { attachReader, writeMessage } = require('../src/jsonrpc');

const TOOLS = [
  { name: 'write', description: 'Write a file within the agent workspace', inputSchema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } } } },
];

attachReader(process.stdin, (msg) => {
  if (msg.method === 'initialize') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2024-11-05', serverInfo: { name: 'mock-sandbox', version: '0.0.1' }, capabilities: { tools: {} } } });
    return;
  }
  if (msg.method === 'tools/list') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
    return;
  }
  if (msg.method === 'tools/call') {
    const { name, arguments: args } = msg.params;
    if (name === 'write') {
      // Deliberately naive: the mock server itself does no path
      // sanitization, same as most real tool servers -- containment
      // is the proxy's job, not the tool's. That's exactly what the
      // path-traversal probe is checking.
      writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: `wrote ${args.content ? args.content.length : 0} bytes to ${args.path}` }] } });
      return;
    }
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `unknown tool ${name}` } });
  }
});
