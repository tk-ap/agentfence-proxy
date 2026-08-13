'use strict';
// Minimal fake MCP tool server used to exercise the proxy end-to-end
// without needing real infrastructure. Implements just enough of the
// protocol (initialize / tools/list / tools/call) over stdio.

const { attachReader, writeMessage } = require('../src/jsonrpc');

const TOOLS = [
  { name: 'search', description: 'Search internal docs', inputSchema: { type: 'object', properties: { query: { type: 'string' } } } },
  { name: 'read', description: 'Read a doc by path', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
  // "write" exists on the live server but is deliberately left out of
  // declared policy — this is what agentfence/drift should catch.
  { name: 'write', description: 'Write a doc by path', inputSchema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } } } },
];

attachReader(process.stdin, (msg) => {
  if (msg.method === 'initialize') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2024-11-05', serverInfo: { name: 'mock-docs', version: '0.0.1' }, capabilities: { tools: {} } } });
    return;
  }
  if (msg.method === 'tools/list') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
    return;
  }
  if (msg.method === 'tools/call') {
    const { name, arguments: args } = msg.params;
    let content;
    if (name === 'search') content = `3 results for "${args.query}"`;
    else if (name === 'read') content = `contents of ${args.path}`;
    else if (name === 'write') content = `wrote ${args.content ? args.content.length : 0} bytes to ${args.path}`;
    else {
      writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `unknown tool ${name}` } });
      return;
    }
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: content }] } });
    return;
  }
});
