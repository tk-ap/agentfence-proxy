'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');

/**
 * Every containment decision (allowed or blocked) is appended to a
 * hash-chained, HMAC-signed JSONL file. Hash-chaining means each record
 * embeds the hash of the previous record, so the file can be checked for
 * tampering or gaps end-to-end — not just verified record-by-record.
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
    const body = {
      ts: new Date().toISOString(),
      ...entry,
      prevHash: this.prevHash,
    };
    const canonical = JSON.stringify(body);
    const recordHash = crypto.createHash('sha256').update(canonical).digest('hex');
    const signature = crypto.createHmac('sha256', this.secret).update(recordHash).digest('hex');

    const record = { ...body, recordHash, signature };
    fs.appendFileSync(this.filePath, JSON.stringify(record) + '\n');
    this.prevHash = recordHash;
    return record;
  }

  /** Walks the file, re-derives each hash/signature, and confirms the chain is unbroken. */
  static verify(filePath, secret) {
    if (!fs.existsSync(filePath)) return { ok: true, checked: 0 };
    const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
    let prevHash = '0'.repeat(64);
    for (let i = 0; i < lines.length; i++) {
      const rec = JSON.parse(lines[i]);
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
    return { ok: true, checked: lines.length };
  }
}

module.exports = { EvidenceLog };
