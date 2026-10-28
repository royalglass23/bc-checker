import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { SignJWT } from 'jose';
import pg from 'pg';
import { requestListener } from '../src/server.mjs';

Object.assign(process.env, {
  APP_BASE_URL: 'https://bc-checker.example.test',
  SERVICEM8_APP_ID: 'test-app',
  SERVICEM8_APP_SECRET: 'test-app-secret',
  SERVICEM8_ALLOWED_ACCOUNT_UUID: '11111111-1111-4111-8111-111111111111',
  DATABASE_URL: 'postgres://unused:unused@localhost/unused',
  TOKEN_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64'),
  SESSION_SECRET: 'test-session-secret-at-least-32-characters',
  CRON_SECRET: 'test-cron-secret-at-least-32-characters',
});

test('OAuth denial is reported without leaking its state, and launch failures identify the failing stage', async () => {
  const originalQuery = pg.Pool.prototype.query;
  const originalError = console.error;
  const originalWarn = console.warn;
  const logs = [];
  let failDashboard = false;
  const usedEvents = new Set();
  pg.Pool.prototype.query = async function (sql, params) {
    if (sql.includes('DELETE FROM oauth_states')) return { rowCount: 1 };
    if (sql.includes('INSERT INTO used_events')) {
      if (usedEvents.has(params[0])) return { rowCount: 0 };
      usedEvents.add(params[0]);
      return { rowCount: 1 };
    }
    if (failDashboard && sql.includes('FROM monitored_jobs')) throw new Error('monitored_jobs table is unavailable');
    if (sql.includes('count(*)::int')) return { rows: [{ total: 0 }] };
    if (sql.includes('FROM monitored_jobs') || sql.includes('FROM consent_candidates') ||
        sql.includes('FROM checker_audit_events')) return { rows: [] };
    throw new Error(`Unexpected query: ${sql}`);
  };
  console.error = (...args) => logs.push(['error', ...args]);
  console.warn = (...args) => logs.push(['warn', ...args]);
  const server = http.createServer(requestListener);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const state = 'private-oauth-state-value-at-least-32-characters';
    const denied = await fetch(`${base}/oauth/callback?error=access_denied&error_description=private-description&state=${state}`);
    assert.equal(denied.status, 403);
    assert.match(await denied.text(), /access was not granted/i);
    assert.ok(logs.some(entry => entry[1] === 'BC Checker OAuth access denied'));
    assert.doesNotMatch(JSON.stringify(logs), /private-oauth-state|private-description/);

    logs.length = 0;
    const rejected = await fetch(`${base}/events`, { method: 'POST', body: 'private-signed-event' });
    assert.equal(rejected.status, 401);
    assert.match((await rejected.json()).eventResponse, /launch rejected/);
    assert.ok(logs.some(entry => entry[1] === 'BC Checker launch failed' && entry[2].stage === 'verify_event'));
    assert.doesNotMatch(JSON.stringify(logs), /private-signed-event/);

    logs.length = 0;
    const eventWithoutId = await new SignJWT({ eventVersion: '1.0', eventName: 'rg_bc_checker_menu',
      auth: { accountUUID: process.env.SERVICEM8_ALLOWED_ACCOUNT_UUID,
        staffUUID: '22222222-2222-4222-8222-222222222222' } })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode(process.env.SERVICEM8_APP_SECRET));
    const missingId = await fetch(`${base}/events`, { method: 'POST', body: eventWithoutId });
    assert.equal(missingId.status, 200);
    assert.match((await missingId.json()).eventResponse, /<h1>BC Checker<\/h1>/);
    const secondMenuClick = await fetch(`${base}/events`, { method: 'POST', body: eventWithoutId });
    assert.equal(secondMenuClick.status, 200);
    assert.equal(usedEvents.size, 0);

    logs.length = 0;
    failDashboard = true;
    const validEvent = await new SignJWT({ eventVersion: '1.0', eventName: 'rg_bc_checker_menu',
      auth: { accountUUID: process.env.SERVICEM8_ALLOWED_ACCOUNT_UUID,
        staffUUID: '22222222-2222-4222-8222-222222222222' }, eventArgs: {} })
      .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setJti('test-event-id')
      .sign(new TextEncoder().encode(process.env.SERVICEM8_APP_SECRET));
    const unavailable = await fetch(`${base}/events`, { method: 'POST', body: validEvent });
    assert.equal(unavailable.status, 401);
    assert.ok(logs.some(entry => entry[1] === 'BC Checker launch failed' &&
      entry[2].stage === 'render_dashboard' && entry[2].error === 'monitored_jobs table is unavailable'));
    logs.length = 0;
    const replay = await fetch(`${base}/events`, { method: 'POST', body: validEvent });
    assert.equal(replay.status, 401);
    assert.ok(logs.some(entry => entry[1] === 'BC Checker launch failed' &&
      entry[2].stage === 'verify_event' && entry[2].error === 'Launch was already used'));
  } finally {
    pg.Pool.prototype.query = originalQuery;
    console.error = originalError;
    console.warn = originalWarn;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
