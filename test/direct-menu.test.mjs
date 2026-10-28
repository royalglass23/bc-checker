import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { test } from 'node:test';
import { SignJWT } from 'jose';
import pg from 'pg';
import { seal } from '../src/db.mjs';
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
  const originalConnect = pg.Pool.prototype.connect;
  const originalFetch = globalThis.fetch;
  const searches = [];
  let roleName = 'Admin';
  let grantStaffScope = true;
  let activityQueries = 0;
  globalThis.fetch = async (url, options) => {
    if (String(url) === 'https://api.servicem8.com/api_1.0/staff.json') return { ok: true, json: async () => [
      { uuid: '22222222-2222-4222-8222-222222222222', first: 'Alex', last: 'Admin', active: 1,
        security_role_uuid: '66666666-6666-4666-8666-666666666666' },
      { uuid: '77777777-7777-4777-8777-777777777777', first: 'Michael', last: 'Example', active: 1 },
      { uuid: '3c6c0cb6-a639-481d-aa1c-24121e810e7b', first: 'Named', last: 'Developer', active: 1,
        security_role_uuid: '99999999-9999-4999-8999-999999999999' },
    ] };
    if (String(url).includes('/securityrole/')) return { ok: true, json: async () => ({ active: 1, name: roleName }) };
    return originalFetch(url, options);
  };
  pg.Pool.prototype.connect = async function () { return { release() {}, async query(sql) {
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) || sql.includes('pg_advisory_xact_lock')) return {};
    if (sql.includes('SELECT * FROM oauth_connections')) return { rows: [{
      expires_at: new Date(Date.now() + 3600_000), access_token_ciphertext: seal('token', Buffer.alloc(32)),
    }] };
    throw new Error(`Unexpected client query: ${sql}`);
  } }; };
  pg.Pool.prototype.query = async function (sql, params) {
    if (sql.includes('INSERT INTO used_events')) return { rowCount: 1, rows: [{ event_hash: 'used' }] };
    if (sql.includes('INSERT INTO checker_audit_events') || sql.includes('UPDATE checker_audit_events')) return { rowCount: 1, rows: [] };
    if (sql.includes('FROM checker_audit_events')) { activityQueries++; return { rows: [{ event_type: 'job_stopped',
      job_number: 'R122', staff_uuid: '77777777-7777-4777-8777-777777777777',
      staff_name: '', outcome: 'success', detail: '',
      created_at: '2026-10-28T00:00:00Z' }, { event_type: 'job_added',
      job_number: 'R121', staff_uuid: '88888888-8888-4888-8888-888888888888',
      staff_name: '', outcome: 'success', detail: '',
      created_at: '2026-10-27T00:00:00Z' }] }; }
    if (sql.includes('FROM monitored_jobs')) searches.push(params?.[2]);
    if (sql.includes('count(*)::int')) return { rows: [{ total: 1 }] };
    if (sql.includes('FROM monitored_jobs')) return { rows: [{ id: '33333333-3333-4333-8333-333333333333',
      job_uuid: '44444444-4444-4444-8444-444444444444', job_number: 'R123',
      job_address: '1 Example Street', client_name: 'Example Client', baseline_complete: false, last_checked_at: null }] };
    if (sql.includes('SELECT scope FROM oauth_connections')) return { rows: [{ scope: `vendor read_jobs read_customers ${grantStaffScope ? 'read_staff read_security_roles' : ''} manage_jobs publish_diary_items` }] };
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
    assert.match(html, /<label for="jobNumbers">Job numbers<\/label>/);
    assert.match(html, /name="jobNumbers" rows="4"/);
    assert.match(html, /Separate ServiceM8 job numbers with commas/);
    assert.match(html, /R123, R124, R125/);
    assert.match(html, /Add Jobs/);
    assert.doesNotMatch(html, /jobFile|xlsx\.js|CSV or XLSX/);
    assert.match(html, /id="jobSearch"/);
    assert.match(html, /Consent candidates for Job R123/);
    assert.match(html, /BC123/);
    assert.match(html, /class="candidate-trigger" data-candidate-dialog="candidate-55555555-5555-4555-8555-555555555555"/);
    assert.match(html, /<dialog id="candidate-55555555-5555-4555-8555-555555555555" class="candidate-dialog"/);
    assert.match(html, /\/candidates\/55555555-5555-4555-8555-555555555555\/delete"/);
    assert.match(html, /Recent checker activity/);
    assert.match(html, /<details><summary><span>Recent checker activity<\/span><\/summary>/);
    assert.match(html, /Stopped monitoring/);
    assert.match(html, /Michael Example/);
    assert.match(html, /Staff member/);
    assert.doesNotMatch(html, /88888888-8888-4888-8888-888888888888/);
    assert.match(html, /action="https:\/\/bc-checker\.example\.test\/jobs\/33333333-3333-4333-8333-333333333333\/stop"/);
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
        body: new URLSearchParams({ session, csrf, jobNumbers: 'R123, !' }),
      });
      assert.equal(add.status, 200);
      assert.equal(errors.at(-1)?.[1]?.error, 'Enter 1–50 valid job numbers separated by commas');
      const addHtml = await add.text();
      assert.match(addHtml, /id="addJobsResult" class="job-dialog error"/);
      assert.match(addHtml, /Jobs not added/);
      assert.match(addHtml, /Enter 1–50 valid job numbers separated by commas/);
      assert.match(addHtml, /id="addJobsLoading" class="job-dialog"/);
    } finally { console.error = originalError; }
    const view = await fetch(`${base}/view`, { method: 'POST',
      body: new URLSearchParams({ session }),
    });
    assert.equal(view.status, 200);
    assert.match(await view.text(), /<h1>BC Checker<\/h1>/);
    roleName = 'Developer';
    const developerView = await fetch(`${base}/view`, { method: 'POST', body: new URLSearchParams({ session }) });
    assert.match(await developerView.text(), /Recent checker activity/);
    roleName = 'Default Business Owner Role';
    const ownerView = await fetch(`${base}/view`, { method: 'POST', body: new URLSearchParams({ session }) });
    assert.match(await ownerView.text(), /Recent checker activity/);
    roleName = 'Staff';
    const queriesBeforeStaffView = activityQueries;
    const staffView = await fetch(`${base}/view`, { method: 'POST', body: new URLSearchParams({ session }) });
    const staffHtml = await staffView.text();
    assert.doesNotMatch(staffHtml, /Recent checker activity|Michael Example|Stopped monitoring/);
    assert.equal(activityQueries, queriesBeforeStaffView);
    roleName = 'Marketing manager ';
    const customRoleView = await fetch(`${base}/view`, { method: 'POST', body: new URLSearchParams({ session }) });
    assert.doesNotMatch(await customRoleView.text(), /Recent checker activity/);
    const allowedSession = await new SignJWT({ accountUUID: process.env.SERVICEM8_ALLOWED_ACCOUNT_UUID,
      staffUUID: '3c6c0cb6-a639-481d-aa1c-24121e810e7b' })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' }).setIssuer('rg-bc-checker-addon')
      .setAudience('bc-checker-staff').setJti(randomUUID()).setIssuedAt().setExpirationTime('5m')
      .sign(new TextEncoder().encode(process.env.SESSION_SECRET));
    const allowedView = await fetch(`${base}/view`, { method: 'POST',
      body: new URLSearchParams({ session: allowedSession }) });
    assert.match(await allowedView.text(), /Recent checker activity/);
    for (const [kind, heading] of [['success', 'Jobs added'], ['partial', 'Some jobs could not be added'], ['error', 'Jobs not added']]) {
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
    grantStaffScope = false;
    const missingStaffScope = await fetch(`${base}/jobs/33333333-3333-4333-8333-333333333333/check`, {
      method: 'POST', body: new URLSearchParams({ session, csrf }),
    });
    assert.equal(missingStaffScope.status, 200);
    assert.match(await missingStaffScope.text(), /Reconnect BC Checker in ServiceM8 to enable staff attribution/);
    const filtered = await fetch(`${base}/view`, { method: 'POST',
      body: new URLSearchParams({ session, search: 'Exam', page: '1' }),
    });
    assert.equal(filtered.status, 200);
    assert.match(await filtered.text(), /value="Exam"/);
    assert.ok(searches.includes('Exam'));
  } finally {
    pg.Pool.prototype.query = originalQuery;
    pg.Pool.prototype.connect = originalConnect;
    globalThis.fetch = originalFetch;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
