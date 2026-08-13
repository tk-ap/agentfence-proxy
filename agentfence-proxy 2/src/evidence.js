'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');

/**
 * Shared hash-chain math used by both evidence log implementations
 * below, so the two never drift from a common definition of what
 * "signed" and "chained" mean.
 */
function sealRecord(body, prevHash, secret) {
  const sealed = { ...body, prevHash };
  const canonical = JSON.stringify(sealed);
  const recordHash = crypto.createHash('sha256').update(canonical).digest('hex');
  const signature = crypto.createHmac('sha256', secret).update(recordHash).digest('hex');
  return { ...sealed, recordHash, signature };
}

function verifyChain(records, secret) {
  let prevHash = '0'.repeat(64);
  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    const { recordHash, signature, ...body } = rec;
    if (body.prevHash !== prevHash) {
      return { ok: false, checked: i, error: `record ${i}: prevHash mismatch (chain broken)` };
    }
    const canonical = JSON.stringify(body);
    const expectedHash = crypto.createHash('sha256').update(canonical).digest('hex');
    if (expectedHash !== recordHash) {
      return { ok: false, checked: i, error: `record ${i}: hash mismatch (record altered)` };
    }
    const expectedSig = crypto.createHmac('sha256', secret).update(recordHash).digest('hex');
    if (expectedSig !== signature) {
      return { ok: false, checked: i, error: `record ${i}: signature invalid` };
    }
    prevHash = recordHash;
  }
  return { ok: true, checked: records.length };
}

/**
 * Every containment decision (allowed or blocked) from REAL agent
 * traffic is appended to a hash-chained, HMAC-signed JSONL file.
 * Hash-chaining means each record embeds the hash of the previous
 * record, so the file can be checked for tampering or gaps end-to-end
 * — not just verified record-by-record.
 *
 * This is a real, checkable evidence trail (not a UI mockup): swap
 * signWithKey() for a KMS/HSM call in production and the format stays
 * the same.
 */
class EvidenceLog {
  constructor(filePath, { secret }) {
    this.filePath = filePath;
    this.secret = secret;
    this.prevHash = this._loadLastHash();
  }

  _loadLastHash() {
    if (!fs.existsSync(this.filePath)) return '0'.repeat(64);
    const lines = fs.readFileSync(this.filePath, 'utf8').trim().split('\n').filter(Boolean);
    if (lines.length === 0) return '0'.repeat(64);
    const last = JSON.parse(lines[lines.length - 1]);
    return last.recordHash;
  }

  record(entry) {
    const record = sealRecord({ ts: new Date().toISOString(), ...entry }, this.prevHash, this.secret);
    fs.appendFileSync(this.filePath, JSON.stringify(record) + '\n');
    this.prevHash = record.recordHash;
    return record;
  }

  /** Walks the file, re-derives each hash/signature, and confirms the chain is unbroken. */
  static verify(filePath, secret) {
    if (!fs.existsSync(filePath)) return { ok: true, checked: 0 };
    const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
    return verifyChain(lines.map((l) => JSON.parse(l)), secret);
  }
}

/**
 * Same hash-chain guarantee, held in memory instead of on disk.
 *
 * Used exclusively for PUBLIC DEMO traffic (see demo-api.js): an
 * anonymous site visitor clicking "run the probe demo" is real
 * containment-decision activity and deserves the same tamper-evident
 * proof in its response, but must NEVER be commingled with, or grow,
 * the durable audit trail that exists for real customer agent
 * traffic. Each request gets its own fresh instance and it's
 * discarded when the response is sent.
 */
class InMemoryEvidenceLog {
  constructor({ secret }) {
    this.secret = secret;
    this.prevHash = '0'.repeat(64);
    this.records = [];
  }

  record(entry) {
    const record = sealRecord({ ts: new Date().toISOString(), ...entry }, this.prevHash, this.secret);
    this.records.push(record);
    this.prevHash = record.recordHash;
    return record;
  }

  verify() {
    return verifyChain(this.records, this.secret);
  }
}

module.exports = { EvidenceLog, InMemoryEvidenceLog };
