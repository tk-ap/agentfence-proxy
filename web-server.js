'use strict';
// Second mock downstream server: web fetch + upload, standing in for
// "the tool that can reach the outside world." The escape scenario in
// test/run-demo.js chains docs.search -> web.fetch -> web.upload to an
// undeclared external host.

const { attachReader, writeMessage } = require('../src/jsonrpc');

const TOOLS = [
  { name: 'fetch', description: 'Fetch a URL', inputSchema: { type: 'object', properties: { url: { type: 'string' } } } },
  // "upload" is live on the server but NOT in declared policy — this is
  // the undeclared-tool block scenario.
  { name: 'upload', description: 'Upload data to a URL', inputSchema: { type: 'object', properties: { url: { type: 'string' }, data: { type: 'string' } } } },
];

attachReader(process.stdin, (msg) => {
  if (msg.method === 'initialize') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2024-11-05', serverInfo: { name: 'mock-web', version: '0.0.1' }, capabilities: { tools: {} } } });
    return;
  }
  if (msg.method === 'tools/list') {
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
    return;
  }
  if (msg.method === 'tools/call') {
    const { name, arguments: args } = msg.params;
    let content;
    if (name === 'fetch') content = `fetched ${args.url} (200 OK, 4kb)`;
    else if (name === 'upload') content = `uploaded ${args.data ? args.data.length : 0} bytes to ${args.url}`;
    else {
      writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `unknown tool ${name}` } });
      return;
    }
    writeMessage(process.stdout, { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: content }] } });
    return;
  }
});
