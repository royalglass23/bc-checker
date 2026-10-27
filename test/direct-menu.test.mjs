import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { test } from 'node:test';
import { SignJWT } from 'jose';
import pg from 'pg';
import { requestListener } from '../src/server.mjs';

test('signed Add-ons menu event renders BC Checker directly in ServiceM8', async () => {
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
  const originalQuery = pg.Pool.prototype.query;
  const searches = [];
  pg.Pool.prototype.query = async function (sql, params) {
    if (sql.includes('INSERT INTO used_events')) return { rowCount: 1, rows: [{ event_hash: 'used' }] };
    if (sql.includes('FROM monitored_jobs')) searches.push(params?.[2]);
    if (sql.includes('count(*)::int')) return { rows: [{ total: 1 }] };
    if (sql.includes('FROM monitored_jobs')) return { rows: [{ id: '33333333-3333-4333-8333-333333333333',
      job_uuid: '44444444-4444-4444-8444-444444444444', job_number: 'R123',
      job_address: '1 Example Street', client_name: 'Example Client', baseline_complete: false, last_checked_at: null }] };
    if (sql.includes('FROM consent_candidates')) return { rows: [{ id: '55555555-5555-4555-8555-555555555555',
      monitored_job_id: '33333333-3333-4333-8333-333333333333', decision: 'needs_review',
      consent_number: 'BC123', action: 'Issued', event_date: '2026-10-28',
      source_url: 'https://homes.co.nz/' }] };
    throw new Error(`Unexpected query: ${sql}`);
  };
  const event = await new SignJWT({ eventVersion: '1.0', eventName: 'rg_bc_checker_menu',
    auth: { accountUUID: process.env.SERVICEM8_ALLOWED_ACCOUNT_UUID,
      staffUUID: '22222222-2222-4222-8222-222222222222' }, eventArgs: {} })
    .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setJti(randomUUID())
    .sign(new TextEncoder().encode(process.env.SERVICEM8_APP_SECRET));
  const server = http.createServer(requestListener);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const response = await fetch(`${base}/events`, { method: 'POST', body: event });
    assert.equal(response.status, 200);
    const { eventResponse: html } = await response.json();
    assert.match(html, /<h1>BC Checker<\/h1>/);
    assert.match(html, /action="https:\/\/bc-checker\.example\.test\/jobs"/);
    assert.match(html, /href="https:\/\/bc-checker\.example\.test\/style\.css"/);
    assert.match(html, /name="session" value="[^"]+"/);
    assert.match(html, /action="https:\/\/bc-checker\.example\.test\/jobs\/33333333-3333-4333-8333-333333333333\/check"/);
    for (const heading of ['Job number', 'Address', 'Client', 'Last checked', 'Status', 'Check', 'Stop']) {
      assert.match(html, new RegExp(`<th scope="col">${heading}</th>`));
    }
    assert.match(html, /<th scope="col">Job number<\/th><th scope="col">Client<\/th><th scope="col">Address<\/th>/);
    assert.match(html, /<tbody><tr><th scope="row">R123<\/th>/);
    assert.match(html, /<tbody><tr><th scope="row">R123<\/th><td class="client-cell">Example Client<\/td><td class="address-cell">1 Example Street<\/td>/);
    assert.match(html, /class="check-job-form" data-job-number="R123"/);
    assert.match(html, /class="icon-button check" type="submit" aria-label="Check now Job R123"/);
    assert.match(html, /id="checkJobLoading" class="job-dialog"/);
    assert.match(html, /class="icon-button stop" type="submit" aria-label="Stop monitoring Job R123"/);
    assert.match(html, /<label for="jobNumber">Job number<\/label>/);
    assert.match(html, /name="jobNumber" type="text"/);
    assert.match(html, /Add Job/);
    assert.doesNotMatch(html, /jobFile|xlsx\.js|CSV or XLSX/);
    assert.match(html, /id="jobSearch"/);
    assert.match(html, /Consent candidates for Job R123/);
    assert.match(html, /BC123/);
    assert.match(html, /action="https:\/\/bc-checker\.example\.test\/jobs\/33333333-3333-4333-8333-333333333333\/stop"/);
    assert.doesNotMatch(html, /<details|<summary/);
    assert.ok(html.indexOf('class="pagination"') > html.indexOf('</table>'));
    assert.ok(html.indexOf('Jobs per page') > html.indexOf('</table>'));
    assert.doesNotMatch(html, /Opening…|Open BC Checker|\/launch/);

    const session = html.match(/name="session" value="([^"]+)"/)?.[1];
    const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
    const originalError = console.error;
    const errors = [];
    console.error = (...args) => errors.push(args);
    try {
      const add = await fetch(`${base}/jobs`, { method: 'POST',
        headers: { Origin: 'null', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ session, csrf, jobNumber: 'R123\nR124' }),
      });
      assert.equal(add.status, 200);
      assert.equal(errors.at(-1)?.[1]?.error, 'Enter one valid job number');
      const addHtml = await add.text();
      assert.match(addHtml, /id="addJobsResult" class="job-dialog error"/);
      assert.match(addHtml, /Job not added/);
      assert.match(addHtml, /Enter one valid job number/);
      assert.match(addHtml, /id="addJobsLoading" class="job-dialog"/);
    } finally { console.error = originalError; }
    const view = await fetch(`${base}/view`, { method: 'POST',
      body: new URLSearchParams({ session }),
    });
    assert.equal(view.status, 200);
    assert.match(await view.text(), /<h1>BC Checker<\/h1>/);
    for (const [kind, heading] of [['success', 'Job added'], ['error', 'Job not added']]) {
      const resultView = await fetch(`${base}/view`, { method: 'POST',
        body: new URLSearchParams({ session, addResult: '1 job added.', addKind: kind }),
      });
      assert.equal(resultView.status, 200);
      const resultHtml = await resultView.text();
      assert.match(resultHtml, new RegExp(heading));
      assert.match(resultHtml, /id="addJobsResult"/);
      assert.match(resultHtml, /1 job added\./);
    }
    for (const [kind, heading] of [['success', 'Job checked'], ['error', 'Job check not completed']]) {
      const resultView = await fetch(`${base}/view`, { method: 'POST',
        body: new URLSearchParams({ session, checkResult: 'Address checked.', checkKind: kind }),
      });
      assert.equal(resultView.status, 200);
      const resultHtml = await resultView.text();
      assert.match(resultHtml, new RegExp(heading));
      assert.match(resultHtml, /id="checkJobResult"/);
      assert.match(resultHtml, /Address checked\./);
    }
    const filtered = await fetch(`${base}/view`, { method: 'POST',
      body: new URLSearchParams({ session, search: 'Exam', page: '1' }),
    });
    assert.equal(filtered.status, 200);
    assert.match(await filtered.text(), /value="Exam"/);
    assert.ok(searches.includes('Exam'));
  } finally {
    pg.Pool.prototype.query = originalQuery;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
