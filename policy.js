'use strict';

const path = require('node:path');

/**
 * The policy engine is intentionally narrow for this scaffold: it proves
 * out the two claims the AgentFence landing page makes, rather than
 * trying to be a general rules engine on day one.
 *
 *   1. "Map effective permissions" — diffPermissions() compares what the
 *      operator DECLARED an agent should be able to reach against what
 *      the downstream servers ACTUALLY expose right now.
 *
 *   2. "Probe hostile paths / gate and prove" — evaluateCall() decides,
 *      per tool invocation, whether the call is in-policy, and returns a
 *      structured reason if not, so every decision is explainable.
 */

function diffPermissions(policy, liveToolsByServer) {
  const declared = policy.declaredTools || {};
  const drift = [];

  for (const [server, tools] of Object.entries(liveToolsByServer)) {
    const declaredTools = new Set(declared[server] || []);
    for (const tool of tools) {
      if (!declaredTools.has(tool)) {
        drift.push({
          type: 'undeclared_tool_reachable',
          server,
          tool,
          detail: `Server "${server}" now exposes tool "${tool}", which is not in declared policy.`,
        });
      }
    }
  }

  for (const [server, tools] of Object.entries(declared)) {
    const liveTools = new Set(liveToolsByServer[server] || []);
    for (const tool of tools) {
      if (!liveTools.has(tool)) {
        drift.push({
          type: 'declared_tool_missing',
          server,
          tool,
          detail: `Policy declares "${server}.${tool}" but the live server does not expose it.`,
        });
      }
    }
  }

  return drift;
}

function getByPath(obj, path) {
  return path.split('.').reduce((acc, key) => (acc == null ? acc : acc[key]), obj);
}

function checkConstraint(constraint, args) {
  const value = getByPath({ args }, constraint.field);

  if (constraint.type === 'domain-allowlist') {
    if (typeof value !== 'string') {
      return { ok: false, reason: `expected string at ${constraint.field}` };
    }
    let host;
    try {
      host = new URL(value).hostname;
    } catch {
      return { ok: false, reason: `"${value}" is not a valid URL` };
    }
    const allowed = constraint.allow.some((d) => host === d || host.endsWith(`.${d}`));
    return allowed
      ? { ok: true }
      : { ok: false, reason: `destination host "${host}" is not in the egress allowlist` };
  }

  if (constraint.type === 'path-prefix-allowlist') {
    if (typeof value !== 'string') {
      return { ok: false, reason: `expected string at ${constraint.field}` };
    }
    // A naive startsWith() check is bypassable: "/workspace/../../etc/passwd"
    // starts with "/workspace/" lexically while resolving somewhere
    // completely different. Normalize first (collapsing "..", "." and
    // repeated slashes) and check the RESOLVED path against the prefix,
    // so traversal sequences can't smuggle the check.
    const resolved = path.posix.normalize('/' + value).replace(/\/+/g, '/');
    const allowed = constraint.allow.some((prefix) => {
      const normalizedPrefix = path.posix.normalize('/' + prefix).replace(/\/+/g, '/');
      return resolved === normalizedPrefix.replace(/\/$/, '')
        || resolved.startsWith(normalizedPrefix.endsWith('/') ? normalizedPrefix : normalizedPrefix + '/');
    });
    return allowed
      ? { ok: true }
      : { ok: false, reason: `path "${value}" resolves to "${resolved}", which is outside allowed prefixes [${constraint.allow.join(', ')}]` };
  }

  return { ok: false, reason: `unknown constraint type "${constraint.type}"` };
}

/**
 * Evaluates a single tool call. Returns:
 *   { allowed: true }
 *   { allowed: false, ruleId, reason }
 */
function evaluateCall(policy, { server, tool, args }) {
  const declaredTools = new Set((policy.declaredTools || {})[server] || []);
  if (!declaredTools.has(tool)) {
    return {
      allowed: false,
      ruleId: 'undeclared-tool',
      reason: `"${server}.${tool}" is not a declared tool for this agent.`,
    };
  }

  const rules = (policy.rules || []).filter((r) => r.server === server && r.tool === tool);
  for (const rule of rules) {
    const result = checkConstraint(rule.constraint, args || {});
    if (!result.ok) {
      return { allowed: false, ruleId: rule.id, reason: result.reason };
    }
  }

  return { allowed: true };
}

module.exports = { diffPermissions, evaluateCall };
