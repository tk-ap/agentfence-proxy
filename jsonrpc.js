'use strict';

const readline = require('node:readline');

/**
 * Attaches a line-delimited JSON-RPC 2.0 reader to a readable stream.
 * MCP's stdio transport frames each message as a single line of JSON.
 * onMessage is called with the parsed object for every valid line;
 * malformed lines are ignored (logged to stderr) rather than crashing
 * the process, since a hostile or buggy downstream server should not
 * be able to take down the proxy.
 */
function attachReader(readableStream, onMessage) {
  const rl = readline.createInterface({ input: readableStream, terminal: false });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (err) {
      process.stderr.write(`[jsonrpc] dropped malformed line: ${trimmed.slice(0, 200)}\n`);
      return;
    }
    onMessage(msg);
  });
  return rl;
}

function writeMessage(writableStream, message) {
  writableStream.write(JSON.stringify(message) + '\n');
}

let nextId = 1;
function newId() {
  return nextId++;
}

module.exports = { attachReader, writeMessage, newId };
