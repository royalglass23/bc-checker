import assert from 'node:assert/strict';
import { test } from 'node:test';
import { finishAudit, recordAudit } from '../src/audit.mjs';
import { runDueChecks } from '../src/checker.mjs';

test('audit entries keep the signed actor and final outcome', async () => {
  const calls = [];
  const client = { query: async (sql, params) => { calls.push({ sql, params }); } };
  const accountUUID = '11111111-1111-4111-8111-111111111111';
  const staffUUID = '22222222-2222-4222-8222-222222222222';
  const id = await recordAudit(client, { accountUUID, jobNumber: 'R123', type: 'manual_check',
    staffUUID, staffName: 'Roxy Example', outcome: 'started' });
  await finishAudit(client, id, 'success', 'Address checked');
  assert.match(calls[0].sql, /INSERT INTO checker_audit_events/);
  assert.deepEqual(calls[0].params.slice(1, 9), [accountUUID, null, 'R123', 'manual_check',
    staffUUID, 'Roxy Example', 'started', '']);
  assert.equal(calls[1].params[0], id);
  assert.deepEqual(calls[1].params.slice(1), ['success', 'Address checked']);
});

test('scheduled checks are logged as system events', async () => {
  const calls = [];
  const row = { id: '33333333-3333-4333-8333-333333333333',
    account_uuid: '11111111-1111-4111-8111-111111111111',
    job_uuid: '44444444-4444-4444-8444-444444444444', job_number: 'R123' };
  const db = {
    async connect() { return { release() {}, async query(sql) {
      if (sql.includes('pg_try_advisory_lock')) return { rows: [{ acquired: true }] };
      if (sql.includes('SELECT * FROM monitored_jobs')) return { rows: [row] };
      if (sql.includes('pg_advisory_unlock')) return { rows: [] };
      throw new Error(`Unexpected lease query: ${sql}`);
    } }; },
    async query(sql, params) { calls.push({ sql, params }); return { rowCount: 1 }; },
  };
  const result = await runDueChecks({}, { database: db,
    checkOne: async () => ({ events: 2, newCandidates: 1 }) });
  assert.equal(result.checked[0].jobNumber, 'R123');
  const insert = calls.find(call => call.sql.includes('INSERT INTO checker_audit_events'));
  const finish = calls.find(call => call.sql.includes('UPDATE checker_audit_events'));
  assert.equal(insert.params[4], 'scheduled_check');
  assert.equal(insert.params[5], null);
  assert.equal(finish.params[1], 'success');
});
