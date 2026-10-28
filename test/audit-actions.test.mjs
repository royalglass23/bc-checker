import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import http from 'node:http';
import { test } from 'node:test';
import { SignJWT } from 'jose';
import pg from 'pg';
import { seal } from '../src/db.mjs';
import { requestListener } from '../src/server.mjs';

test('add, stop, BC decision and manual check audit the signed staff member', async () => {
  Object.assign(process.env, {
    APP_BASE_URL: 'https://bc-checker.example.test', SERVICEM8_APP_ID: 'test-app',
    SERVICEM8_APP_SECRET: 'test-secret',
    SERVICEM8_ALLOWED_ACCOUNT_UUID: '11111111-1111-4111-8111-111111111111',
    DATABASE_URL: 'postgres://unused:unused@localhost/unused',
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64'),
    SESSION_SECRET: 'test-session-secret-at-least-32-characters',
    CRON_SECRET: 'test-cron-secret-at-least-32-characters',
  });
  const accountUUID = process.env.SERVICEM8_ALLOWED_ACCOUNT_UUID;
  const staffUUID = '22222222-2222-4222-8222-222222222222';
  const jobUUID = '44444444-4444-4444-8444-444444444444';
  const jobId = '33333333-3333-4333-8333-333333333333';
  const candidateId = '55555555-5555-4555-8555-555555555555';
  const jti = randomUUID();
  const session = await new SignJWT({ accountUUID, staffUUID })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' }).setIssuer('rg-bc-checker-addon')
    .setAudience('bc-checker-staff').setJti(jti).setIssuedAt().setExpirationTime('5m')
    .sign(new TextEncoder().encode(process.env.SESSION_SECRET));
  const csrf = createHash('sha256').update(`${jti}:${process.env.SESSION_SECRET}`).digest('hex');
  const audits = [];
  const originalQuery = pg.Pool.prototype.query;
  const originalConnect = pg.Pool.prototype.connect;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (String(url).startsWith('https://api.servicem8.com/api_1.0/job.json')) {
      return { ok: true, json: async () => [{ uuid: jobUUID, generated_job_id: 'R124',
        job_address: '1 Example Street', company_uuid: '' }] };
    }
    return originalFetch(url, options);
  };
  pg.Pool.prototype.query = async function (sql, params) {
    if (sql.includes('SELECT scope FROM oauth_connections')) return { rows: [{ scope: '' }] };
    if (sql.includes('SELECT * FROM monitored_jobs WHERE id=')) return { rows: [{ id: jobId,
      account_uuid: accountUUID, job_uuid: jobUUID, job_number: 'R123' }] };
    if (sql.includes('INSERT INTO checker_audit_events')) { audits.push(params); return { rowCount: 1 }; }
    if (sql.includes('UPDATE checker_audit_events')) return { rowCount: 1 };
    if (sql.includes('count(*)::int')) return { rows: [{ total: 0 }] };
    if (sql.includes('FROM monitored_jobs') || sql.includes('FROM consent_candidates') ||
        sql.includes('FROM checker_audit_events')) return { rows: [] };
    throw new Error(`Unexpected query: ${sql}`);
  };
  pg.Pool.prototype.connect = async function () {
    return { release() {}, async query(sql, params) {
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') return {};
      if (sql.includes('pg_advisory_xact_lock')) return {};
      if (sql.includes('SELECT * FROM oauth_connections')) return { rows: [{
        expires_at: new Date(Date.now() + 3600_000),
        access_token_ciphertext: seal('token', Buffer.alloc(32)),
      }] };
      if (sql.includes('INSERT INTO monitored_jobs')) return { rowCount: 1, rows: [{ id: jobId }] };
      if (sql.includes('DELETE FROM consent_candidates')) return { rowCount: 0 };
      if (sql.includes("UPDATE monitored_jobs SET status='stopped'")) return { rows: [{ job_uuid: jobUUID, job_number: 'R123' }] };
      if (sql.includes('SELECT c.id, c.monitored_job_id')) return { rows: [{ id: candidateId,
        monitored_job_id: jobId, consent_number: 'BC123', job_uuid: jobUUID, job_number: 'R123' }] };
      if (sql.includes('UPDATE consent_candidates')) return { rowCount: 1 };
      if (sql.includes('INSERT INTO checker_audit_events')) { audits.push(params); return { rowCount: 1 }; }
      throw new Error(`Unexpected client query: ${sql}`);
    } };
  };
  const server = http.createServer(requestListener);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const add = await fetch(`${base}/jobs`, { method: 'POST',
      body: new URLSearchParams({ session, csrf, jobNumbers: 'R124' }) });
    assert.equal(add.status, 200);
    for (const path of [`/jobs/${jobId}/stop`, `/candidates/${candidateId}/ignore`, `/jobs/${jobId}/check`]) {
      const response = await fetch(`${base}${path}`, { method: 'POST',
        body: new URLSearchParams({ session, csrf }) });
      assert.equal(response.status, 200);
    }
    assert.deepEqual(audits.map(params => params[4]), ['job_added', 'job_stopped', 'bc_ignored', 'manual_check']);
    assert.ok(audits.every(params => params[1] === accountUUID && params[5] === staffUUID));
  } finally {
    pg.Pool.prototype.query = originalQuery;
    pg.Pool.prototype.connect = originalConnect;
    globalThis.fetch = originalFetch;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
