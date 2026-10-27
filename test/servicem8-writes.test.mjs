import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { addDiaryItem, addJobNote, exchangeCode, scopes } from '../src/servicem8.mjs';

test('add-on manifest requests the same ServiceM8 scopes as OAuth', async () => {
  const manifest = JSON.parse(await readFile(new URL('../public/manifest.json', import.meta.url)));
  assert.equal(manifest.oauth.scope, scopes);
});

test('read-only ServiceM8 grant can fetch jobs while missing read permission is rejected', async () => {
  const original = globalThis.fetch;
  let granted = 'vendor read_jobs';
  globalThis.fetch = async () => ({ ok: true, json: async () => ({
    access_token: 'access', refresh_token: 'refresh', expires_in: 3600, scope: granted,
  }) });
  try {
    const cfg = { appId: 'app', appSecret: 'secret', baseUrl: 'https://bc-checker.example.test' };
    const tokens = await exchangeCode(cfg, 'code');
    assert.equal(tokens.scope, 'vendor read_jobs');
    granted = 'vendor publish_job_notes publish_diary_items';
    await assert.rejects(exchangeCode(cfg, 'code'), /ServiceM8 permissions are incomplete/);
  } finally { globalThis.fetch = original; }
});

test('manual check writes use separate Job Note and attributed Diary endpoints', async () => {
  assert.match(scopes, /publish_job_notes/);
  assert.match(scopes, /publish_diary_items/);
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 201 };
  };
  try {
    const jobUUID = '44444444-4444-4444-8444-444444444444';
    await addJobNote('token', jobUUID, 'Checked address');
    await addDiaryItem('token', jobUUID, 'Checked address');
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, 'https://api.servicem8.com/api_1.0/note.json');
    assert.deepEqual(JSON.parse(calls[0].options.body), { related_object: 'job',
      related_object_uuid: jobUUID, note: 'Checked address' });
    assert.equal(calls[1].url, 'https://api.servicem8.com/api_1.0/diary.json');
    assert.deepEqual(JSON.parse(calls[1].options.body), { job_uuid: jobUUID, content: 'Checked address' });
    assert.equal(calls[0].options.headers.Authorization, 'Bearer token');
  } finally { globalThis.fetch = original; }
});
