import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { addDiaryItem, exchangeCode, getClientName, getStaffName, scopes, updateJobNoteField } from '../src/servicem8.mjs';
import { mergeBcStatus } from '../src/bc-note.mjs';
import { manualCheckDiaryContent } from '../src/server.mjs';

test('add-on manifest requests the same ServiceM8 scopes as OAuth', async () => {
  const manifest = JSON.parse(await readFile(new URL('../public/manifest.json', import.meta.url)));
  assert.equal(manifest.oauth.scope, scopes);
});

test('ServiceM8 grant must allow reading jobs and clients', async () => {
  const original = globalThis.fetch;
  let granted = 'vendor read_jobs read_customers';
  globalThis.fetch = async () => ({ ok: true, json: async () => ({
    access_token: 'access', refresh_token: 'refresh', expires_in: 3600, scope: granted,
  }) });
  try {
    const cfg = { appId: 'app', appSecret: 'secret', baseUrl: 'https://bc-checker.example.test' };
    const tokens = await exchangeCode(cfg, 'code');
    assert.equal(tokens.scope, 'vendor read_jobs read_customers');
    granted = 'vendor read_jobs';
    await assert.rejects(exchangeCode(cfg, 'code'), /ServiceM8 permissions are incomplete/);
  } finally { globalThis.fetch = original; }
});

test('client name is read from the linked ServiceM8 Client', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    assert.equal(url, 'https://api.servicem8.com/api_1.0/company/11111111-1111-4111-8111-111111111111.json');
    return { ok: true, json: async () => ({ name: 'Example Client' }) };
  };
  try {
    assert.equal(await getClientName('token', '11111111-1111-4111-8111-111111111111'), 'Example Client');
    assert.equal(await getClientName('token', ''), '');
  } finally { globalThis.fetch = original; }
});

test('staff name is resolved from the signed staff UUID', async () => {
  const original = globalThis.fetch;
  const staffUUID = '22222222-2222-4222-8222-222222222222';
  globalThis.fetch = async url => {
    assert.equal(url, `https://api.servicem8.com/api_1.0/staff/${staffUUID}.json`);
    return { ok: true, json: async () => ({ first: 'Michael', last: 'Example' }) };
  };
  try {
    assert.equal(await getStaffName('token', staffUUID), 'Michael Example');
  } finally { globalThis.fetch = original; }
});

test('manual check Diary entry names the staff member who triggered it', () => {
  const content = manualCheckDiaryContent({ job_number: 'R123', job_address: '1 Example Street' },
    { events: 2, firstCheck: false, newCandidates: 1, sourceUrl: 'https://example.test/source' },
    'Roxy Example', '28/10/2026, 12:31 pm');
  assert.match(content, /Checked by: Roxy Example/);
  assert.match(content, /Job R123: 1 Example Street/);
  assert.match(content, /1 new candidate\(s\) to review/);
});

test('manual check updates the Job Note field and creates one Diary item', async () => {
  assert.match(scopes, /manage_jobs/);
  assert.match(scopes, /publish_diary_items/);
  assert.match(scopes, /read_staff/);
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (!options?.method) return { ok: true, json: async () => ({ customfield_note_: calls.length === 1
      ? 'Staff note | NO BC - 20 Oct 2026' : 'Staff note | BC - BC123 - 28 Oct 2026' }) };
    return { ok: true, status: 201 };
  };
  try {
    const jobUUID = '44444444-4444-4444-8444-444444444444';
    await updateJobNoteField('token', jobUUID, current => mergeBcStatus(current, 'BC - BC123 - 28 Oct 2026'));
    const staffUUID = '22222222-2222-4222-8222-222222222222';
    await addDiaryItem('token', jobUUID, 'Checked address', staffUUID);
    assert.equal(calls.length, 4);
    assert.equal(calls[1].url, `https://api.servicem8.com/api_1.0/job/${jobUUID}.json`);
    assert.deepEqual(JSON.parse(calls[1].options.body), { customfield_note_: 'Staff note | BC - BC123 - 28 Oct 2026' });
    assert.equal(calls[3].url, 'https://api.servicem8.com/api_1.0/diary.json');
    assert.deepEqual(JSON.parse(calls[3].options.body), { job_uuid: jobUUID, content: 'Checked address' });
    assert.equal(calls[1].options.headers.Authorization, 'Bearer token');
    assert.equal(calls[1].options.headers['x-impersonate-uuid'], undefined);
    assert.equal(calls[3].options.headers['x-impersonate-uuid'], staffUUID);
    assert.equal(calls.filter(call => call.url.endsWith('/note.json')).length, 0);
  } finally { globalThis.fetch = original; }
});
