'use strict';

const { attachReader, writeMessage } = require('./jsonrpc');
const { evaluateCall, diffPermissions } = require('./policy');
const { buildProbes, scoreResults } = require('./prober');

/**
 * ProxyServer holds all containment logic and is transport-agnostic: it
 * exposes handleMessage(msg) -> Promise<responseObject|null>, and each
 * transport (stdio, HTTP) is a thin adapter that feeds it messages and
 * writes back whatever it returns. This is what let HTTP/SSE get added
 * without touching the policy engine, evidence log, or tool-call logic.
 *
 *   - forwards tools/list, merging results from every downstream server
 *     and tagging each tool with "declared: true/false" against policy
 *   - intercepts tools/call, runs evaluateCall(), and either forwards
 *     to the real server or returns a policy-block error
 *   - writes an evidence record for every call, allowed or blocked
 *   - exposes a non-standard "agentfence/drift" method an operator or
 *     CI job can call to pull the current effective-permissions diff
 *   - exposes a non-standard "agentfence/probe" method that generates
 *     and fires adversarial calls at itself (through the SAME policy
 *     path real traffic takes) and returns a containment scorecard —
 *     probe traffic is tagged source:'probe' in the evidence log so
 *     it's distinguishable from real agent activity
 */
class ProxyServer {
  constructor({ downstreams, policy, evidenceLog }) {
    this.downstreams = downstreams; // Map<serverName, DownstreamClient>
    this.policy = policy;
    this.evidenceLog = evidenceLog;
    this.toolIndex = new Map(); // "server.tool" -> { server, tool }
  }

  /** Wires this proxy up to a local agent talking line-delimited JSON-RPC over stdio. */
  attachStdio(input, output) {
    attachReader(input, (msg) => {
      this.handleMessage(msg)
        .then((res) => { if (res) writeMessage(output, res); })
        .catch((err) => writeMessage(output, this._errorEnvelope(msg && msg.id, -32000, err.message)));
    });
  }

  _okEnvelope(id, result) {
    return { jsonrpc: '2.0', id, result };
  }

  _errorEnvelope(id, code, message) {
    return { jsonrpc: '2.0', id, error: { code, message } };
  }

  async _listAllTools() {
    const liveToolsByServer = {};
    const flatTools = [];
    for (const [serverName, client] of this.downstreams.entries()) {
      const result = await client.request('tools/list', {});
      const tools = (result && result.tools) || [];
      liveToolsByServer[serverName] = tools.map((t) => t.name);
      const declaredTools = new Set((this.policy.declaredTools || {})[serverName] || []);
      for (const t of tools) {
        flatTools.push({
          name: `${serverName}.${t.name}`,
          description: t.description,
          inputSchema: t.inputSchema,
          _agentfence: { server: serverName, declared: declaredTools.has(t.name) },
        });
        this.toolIndex.set(`${serverName}.${t.name}`, { server: serverName, tool: t.name });
      }
    }
    return { flatTools, liveToolsByServer };
  }

  /**
   * Handles exactly one JSON-RPC message and resolves to the response
   * object, or null for notifications (messages with no "id", which per
   * JSON-RPC never get a response). Never throws -- transport adapters
   * can call this without their own try/catch for protocol errors, only
   * for transport-level failures (bad JSON, etc).
   */
  async handleMessage(msg) {
    if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || !msg.method) {
      return this._errorEnvelope(msg && msg.id, -32600, 'invalid JSON-RPC request');
    }

    const hasId = msg.id !== undefined && msg.id !== null;

    if (msg.method === 'notifications/initialized') {
      return null; // notification, no response expected
    }

    if (msg.method === 'initialize') {
      return this._okEnvelope(msg.id, {
        protocolVersion: '2025-03-26',
        serverInfo: { name: 'agentfence-proxy', version: '0.2.0' },
        capabilities: { tools: {} },
      });
    }

    if (msg.method === 'tools/list') {
      const { flatTools } = await this._listAllTools();
      return this._okEnvelope(msg.id, { tools: flatTools });
    }

    if (msg.method === 'agentfence/drift') {
      const { liveToolsByServer } = await this._listAllTools();
      const drift = diffPermissions(this.policy, liveToolsByServer);
      return this._okEnvelope(msg.id, { drift, checkedAt: new Date().toISOString() });
    }

    if (msg.method === 'agentfence/probe') {
      const scorecard = await this._runProbes();
      return this._okEnvelope(msg.id, scorecard);
    }

    if (msg.method === 'tools/call') {
      return this._handleToolCall(msg, 'agent');
    }

    if (!hasId) return null; // unknown notification -- drop silently per spec
    return this._errorEnvelope(msg.id, -32601, `method not found: ${msg.method}`);
  }

  async _handleToolCall(msg, source = 'agent') {
    const flatName = msg.params && msg.params.name;
    const args = (msg.params && msg.params.arguments) || {};
    let entry = this.toolIndex.get(flatName);

    // A spec-compliant client always calls tools/list before tools/call,
    // but the toolIndex is only populated as a side effect of that call.
    // A client that skips straight to tools/call (or a fresh proxy
    // instance that hasn't seen a listing yet) would otherwise get a
    // false "unknown tool" block on a perfectly legitimate, declared
    // tool — a false positive that's worse for a containment product's
    // credibility than the extra downstream round trip costs. Refresh
    // once before concluding the tool genuinely doesn't exist.
    if (!entry) {
      await this._listAllTools();
      entry = this.toolIndex.get(flatName);
    }

    if (!entry) {
      const record = this.evidenceLog.record({
        decision: 'blocked',
        source,
        ruleId: 'unknown-tool',
        tool: flatName,
        args,
        reason: `"${flatName}" is not a known tool on any connected server.`,
      });
      return this._errorEnvelope(msg.id, -32001, `blocked by AgentFence [${record.recordHash.slice(0, 12)}]: unknown tool`);
    }

    const { server, tool } = entry;
    const decision = evaluateCall(this.policy, { server, tool, args });

    if (!decision.allowed) {
      const record = this.evidenceLog.record({
        decision: 'blocked',
        source,
        ruleId: decision.ruleId,
        server,
        tool,
        args,
        reason: decision.reason,
      });
      return this._errorEnvelope(
        msg.id,
        -32001,
        `blocked by AgentFence [${record.recordHash.slice(0, 12)}]: ${decision.reason}`
      );
    }

    const client = this.downstreams.get(server);
    try {
      const result = await client.request('tools/call', { name: tool, arguments: args });
      this.evidenceLog.record({ decision: 'allowed', source, server, tool, args });
      return this._okEnvelope(msg.id, result);
    } catch (err) {
      this.evidenceLog.record({ decision: 'error', source, server, tool, args, reason: err.message });
      return this._errorEnvelope(msg.id, -32002, `downstream error: ${err.message}`);
    }
  }

  /**
   * Generates an adversarial probe battery from the CURRENT policy and
   * live tool state, fires each one through the exact same
   * _handleToolCall() path real agent traffic takes (so a probe result
   * is proof about the real enforcement path, not a separate simulation
   * that could drift from it), and returns a scorecard.
   *
   * Every probe call is logged to the evidence trail tagged
   * source:'probe' so operators can tell red-team activity apart from
   * genuine agent traffic when reading the log.
   */
  async _runProbes() {
    const { liveToolsByServer } = await this._listAllTools();
    const drift = diffPermissions(this.policy, liveToolsByServer);
    const probes = buildProbes(this.policy, liveToolsByServer, drift);

    const results = [];
    for (const probe of probes) {
      const syntheticMsg = { jsonrpc: '2.0', id: `probe:${probe.id}`, method: 'tools/call', params: { name: probe.name, arguments: probe.arguments } };
      const response = await this._handleToolCall(syntheticMsg, 'probe');
      results.push({ ...probe, actualBlocked: !!response.error });
    }

    const scorecard = scoreResults(results);
    this.evidenceLog.record({
      decision: 'probe-run-complete',
      source: 'probe',
      containmentScore: scorecard.containmentScore,
      attackProbes: scorecard.attackProbes,
      caught: scorecard.caught,
      missedCount: scorecard.missed.length,
      falsePositiveCount: scorecard.falsePositives.length,
    });

    return { ...scorecard, runAt: new Date().toISOString(), probesRun: probes.length };
  }
}

module.exports = { ProxyServer };
