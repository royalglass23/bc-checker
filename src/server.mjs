import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import manifest from '../manifest.json' with { type: 'json' };
import { SignJWT, jwtVerify } from 'jose';
import { config } from './config.mjs';
import { database } from './db.mjs';
import { runDueChecks } from './checker.mjs';
import { parseJobNumbers } from './domain.mjs';
import { accessToken, consumeOAuthState, createOAuthState, exchangeCode,
  getJobByNumber, oauthAuthorizeUrl, saveConnection, vendorUUID } from './servicem8.mjs';

const cfg = config();
const db = database(cfg);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const textKey = new TextEncoder().encode(cfg.sessionSecret);
const appOrigin = new URL(cfg.baseUrl).origin;

const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);

function respond(res, code, body, type = 'text/html; charset=utf-8', extras = {}) {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', ...extras });
  res.end(body);
}

function redirect(res, location, extras = {}) {
  res.writeHead(303, { Location: location, 'Cache-Control': 'no-store', ...extras });
  res.end();
}

async function bodyText(req, limit = 100_000) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error('Request is too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function cookie(req, name) {
  return req.headers.cookie?.split(';').map(item => item.trim()).find(item => item.startsWith(`${name}=`))?.slice(name.length + 1) ?? '';
}

async function issueSession(identity, audience, ttlSeconds) {
  return new SignJWT({ accountUUID: identity.accountUUID, staffUUID: identity.staffUUID })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' }).setIssuer('rg-bc-checker-addon')
    .setAudience(audience).setJti(randomUUID()).setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`).sign(textKey);
}

async function verifySession(token, audience) {
  const { payload } = await jwtVerify(token, textKey, { algorithms: ['HS256'],
    issuer: 'rg-bc-checker-addon', audience });
  if (!uuid.test(String(payload.accountUUID)) || !uuid.test(String(payload.staffUUID)) ||
    String(payload.accountUUID).toLowerCase() !== cfg.allowedAccountUUID) throw new Error('Invalid staff session');
  return { accountUUID: String(payload.accountUUID).toLowerCase(),
    staffUUID: String(payload.staffUUID).toLowerCase(), jti: String(payload.jti) };
}

async function staff(req, res) {
  try { return await verifySession(cookie(req, 'bc_session'), 'bc-checker-staff'); }
  catch { respond(res, 401, '<h1>Session expired</h1><p>Open BC Checker from ServiceM8 again.</p>'); return null; }
}

function csrfFor(identity) {
  return createHash('sha256').update(`${identity.jti}:${cfg.sessionSecret}`).digest('hex');
}

function checkForm(req, params, identity) {
  if (req.headers.origin !== appOrigin) throw new Error('Invalid request origin');
  const given = Buffer.from(params.get('csrf') ?? '');
  const expected = Buffer.from(csrfFor(identity));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new Error('Invalid form token');
}

async function verifyEvent(token) {
  if (!token || token.length > 16_384 || token.split('.').length !== 3) throw new Error('Invalid launch');
  const { payload, protectedHeader } = await jwtVerify(token, new TextEncoder().encode(cfg.appSecret),
    { algorithms: ['HS256'], clockTolerance: 30 });
  if (protectedHeader.alg !== 'HS256' || payload.eventVersion !== '1.0' ||
    String(payload.eventName).toLowerCase() !== 'rg_bc_checker_menu' ||
    !uuid.test(String(payload.auth?.accountUUID)) || !uuid.test(String(payload.auth?.staffUUID)) ||
    String(payload.auth.accountUUID).toLowerCase() !== cfg.allowedAccountUUID ||
    !(Array.isArray(payload.eventArgs) && payload.eventArgs.length === 0 ||
      payload.eventArgs && typeof payload.eventArgs === 'object' &&
      !Array.isArray(payload.eventArgs) && Object.keys(payload.eventArgs).length === 0) ||
    !Number.isInteger(payload.iat) || !payload.jti ||
    Date.now() / 1000 - payload.iat > 300 || payload.iat - Date.now() / 1000 > 30) {
    throw new Error('Invalid launch');
  }
  const eventHash = createHash('sha256').update(`${payload.auth.accountUUID}:${payload.jti}`).digest('hex');
  const used = await db.query(`INSERT INTO used_events (event_hash, expires_at)
    VALUES ($1, now() + interval '10 minutes') ON CONFLICT DO NOTHING RETURNING event_hash`, [eventHash]);
  if (used.rowCount !== 1) throw new Error('Launch was already used');
  return { accountUUID: String(payload.auth.accountUUID).toLowerCase(),
    staffUUID: String(payload.auth.staffUUID).toLowerCase() };
}

function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · RG BC Checker</title><link rel="stylesheet" href="/style.css"></head><body><main>${body}</main><script src="/app.js" defer></script></body></html>`;
}

function actionForm(path, label, csrf, extra = '') {
  return `<form method="post" action="${escape(path)}"><input type="hidden" name="csrf" value="${csrf}">${extra}<button type="submit">${escape(label)}</button></form>`;
}

async function dashboard(req, res) {
  const identity = await staff(req, res);
  if (!identity) return;
  const jobs = await db.query('SELECT * FROM monitored_jobs WHERE account_uuid=$1 AND status=$2 ORDER BY created_at DESC',
    [identity.accountUUID, 'active']);
  const candidates = await db.query(`SELECT c.* FROM consent_candidates c JOIN monitored_jobs j ON j.id=c.monitored_job_id
    WHERE j.account_uuid=$1 AND j.status='active' ORDER BY c.first_seen_at DESC`, [identity.accountUUID]);
  const byJob = Map.groupBy(candidates.rows, row => row.monitored_job_id);
  const csrf = csrfFor(identity);
  const cards = jobs.rows.map(job => {
    const rows = byJob.get(job.id) ?? [];
    const review = rows.filter(row => row.decision === 'needs_review').length;
    const renderCandidate = row => `<li class="candidate ${escape(row.decision)}">
      <div><strong>${escape(row.consent_number || 'Number unavailable')}</strong> · ${escape(row.action || 'Status unclear')} · ${escape(row.event_date || 'Date unavailable')}
      <span class="pill">${escape(row.decision.replace('_', ' '))}</span></div>
      ${row.description ? `<p>${escape(row.description)}</p>` : ''}
      <a href="${escape(row.source_url)}" target="_blank" rel="noopener noreferrer">View property source</a>
      <div class="actions">${row.decision === 'ignored'
        ? actionForm(`/candidates/${row.id}/reopen`, 'Reopen for review', csrf)
        : `${actionForm(`/candidates/${row.id}/ignore`, 'Wrong BC', csrf)}
           ${actionForm(`/candidates/${row.id}/confirm`, 'Right BC — stop checking', csrf)}`}</div></li>`;
    const events = rows.filter(row => row.decision !== 'ignored').map(renderCandidate).join('');
    const ignored = rows.filter(row => row.decision === 'ignored').map(renderCandidate).join('');
    return `<article class="job"><div class="job-head"><div><h2>Job ${escape(job.job_number)}</h2><p>${escape(job.job_address)}</p></div>
      <span class="pill ${review ? 'attention' : ''}">${review ? `${review} to review` : job.baseline_complete ? 'Monitoring' : 'Waiting for first check'}</span></div>
      ${job.job_description ? `<p class="description">${escape(job.job_description.slice(0, 350))}</p>` : ''}
      <p class="meta">Last checked: ${job.last_checked_at ? escape(new Date(job.last_checked_at).toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' })) : 'Never'}
      ${job.last_error ? `<br><span class="error">Check failed: ${escape(job.last_error)}</span>` : ''}</p>
      ${events ? `<ul>${events}</ul>` : `<p class="empty">No consent candidates recorded yet.</p>`}
      ${ignored ? `<details><summary>${rows.filter(row => row.decision === 'ignored').length} dismissed candidate(s)</summary><ul>${ignored}</ul></details>` : ''}
      <details><summary>Stop monitoring this job</summary>${actionForm(`/jobs/${job.id}/stop`, 'Remove from monitoring', csrf)}</details>
      </article>`;
  }).join('');
  const flash = new URL(req.url, cfg.baseUrl).searchParams.get('message');
  const html = page('Monitored jobs', `<header><p class="eyebrow">Royal Glass · ServiceM8 add-on</p><h1>BC Checker</h1>
    <p>Track Auckland jobs every 14 days. Existing consents form a baseline; only newly seen candidates need review.</p></header>
    ${flash ? `<p class="flash" role="status">${escape(flash.slice(0, 300))}</p>` : ''}
    <section class="add"><h2>Add jobs</h2><p>Paste job numbers, one per line, or load a CSV export. The first column should contain the job number.</p>
    <form method="post" action="/jobs"><input type="hidden" name="csrf" value="${csrf}">
    <label for="jobNumbers">Job numbers</label><textarea id="jobNumbers" name="jobNumbers" rows="5" maxlength="20000" required></textarea>
    <label for="csvFile">Or choose a CSV file</label><input id="csvFile" type="file" accept=".csv,text/csv">
    <button type="submit">Add to monitoring</button></form></section>
    <section aria-label="Monitored jobs"><h2>${jobs.rows.length} active ${jobs.rows.length === 1 ? 'job' : 'jobs'}</h2>
    ${cards || '<p class="empty">No jobs are being monitored. Add a job number to start.</p>'}</section>`);
  respond(res, 200, html, 'text/html; charset=utf-8', {
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
}

async function addJobs(req, res) {
  const identity = await staff(req, res);
  if (!identity) return;
  const params = new URLSearchParams(await bodyText(req, 25_000));
  checkForm(req, params, identity);
  const numbers = parseJobNumbers(params.get('jobNumbers'));
  if (numbers.length === 0 || numbers.length > 50) throw new Error('Enter 1–50 valid job numbers');
  const token = await accessToken(cfg, identity.accountUUID);
  let added = 0;
  const failures = [];
  for (const number of numbers) {
    try {
      const job = await getJobByNumber(token, number);
      if (!uuid.test(job.uuid) || !job.job_address?.trim()) throw new Error('Job has no usable address');
      const client = await db.connect();
      try {
        await client.query('BEGIN');
        const result = await client.query(`INSERT INTO monitored_jobs
          (id, account_uuid, job_uuid, job_number, job_address, job_description, added_by_staff_uuid)
          VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (account_uuid, job_uuid) DO UPDATE SET
          job_number=excluded.job_number, job_address=excluded.job_address,
          job_description=excluded.job_description, status='active', baseline_complete=false,
          last_checked_at=NULL, next_check_at=now(), last_error=NULL,
          added_by_staff_uuid=excluded.added_by_staff_uuid,
          stopped_by_staff_uuid=NULL, stopped_at=NULL
          WHERE monitored_jobs.status='stopped' RETURNING id`,
        [randomUUID(), identity.accountUUID, job.uuid, number, job.job_address,
          String(job.job_description ?? '').slice(0, 2000), identity.staffUUID]);
        if (result.rowCount) {
          await client.query('DELETE FROM consent_candidates WHERE monitored_job_id=$1', [result.rows[0].id]);
          added++;
        }
        await client.query('COMMIT');
      } catch (error) { await client.query('ROLLBACK'); throw error; }
      finally { client.release(); }
    } catch { failures.push(number); }
  }
  const message = `${added} job${added === 1 ? '' : 's'} added.${failures.length ? ` Could not add: ${failures.join(', ').slice(0, 160)}.` : ''}`;
  redirect(res, `/?message=${encodeURIComponent(message)}`);
}

async function decision(req, res, candidateId, value) {
  const identity = await staff(req, res);
  if (!identity) return;
  const params = new URLSearchParams(await bodyText(req));
  checkForm(req, params, identity);
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const candidate = await client.query(`SELECT c.id, c.monitored_job_id FROM consent_candidates c
      JOIN monitored_jobs j ON j.id=c.monitored_job_id WHERE c.id=$1 AND j.account_uuid=$2 AND j.status='active' FOR UPDATE OF c`,
    [candidateId, identity.accountUUID]);
    if (!candidate.rows[0]) throw new Error('Candidate is no longer active');
    await client.query(`UPDATE consent_candidates SET decision=$2, decided_by_staff_uuid=$3,
      decided_at=now() WHERE id=$1`, [candidateId, value, identity.staffUUID]);
    if (value === 'confirmed') await client.query(`UPDATE monitored_jobs SET status='stopped',
      stopped_by_staff_uuid=$2, stopped_at=now() WHERE id=$1 AND account_uuid=$3`,
    [candidate.rows[0].monitored_job_id, identity.staffUUID, identity.accountUUID]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
  const message = value === 'confirmed' ? 'Right BC recorded; job removed from monitoring.' :
    value === 'ignored' ? 'Wrong BC saved; monitoring continues.' : 'Candidate reopened for review.';
  redirect(res, `/?message=${encodeURIComponent(message)}`);
}

async function stopJob(req, res, jobId) {
  const identity = await staff(req, res);
  if (!identity) return;
  const params = new URLSearchParams(await bodyText(req));
  checkForm(req, params, identity);
  await db.query(`UPDATE monitored_jobs SET status='stopped', stopped_by_staff_uuid=$3,
    stopped_at=now() WHERE id=$1 AND account_uuid=$2 AND status='active'`,
  [jobId, identity.accountUUID, identity.staffUUID]);
  redirect(res, '/?message=Job%20removed%20from%20monitoring.');
}

async function handle(req, res) {
  const url = new URL(req.url, cfg.baseUrl);
  const path = url.pathname;
  if (req.method === 'GET' && path === '/health') return respond(res, 200, 'ok', 'text/plain');
  if (req.method === 'GET' && path === '/manifest.json') return respond(res, 200, JSON.stringify(manifest), 'application/json');
  if (req.method === 'GET' && path === '/style.css') return respond(res, 200, await readFile(new URL('./style.css', import.meta.url)), 'text/css');
  if (req.method === 'GET' && path === '/app.js') return respond(res, 200, await readFile(new URL('./app.js', import.meta.url)), 'text/javascript');
  if (req.method === 'GET' && path === '/icon.svg') return respond(res, 200, await readFile(new URL('./icon.svg', import.meta.url)), 'image/svg+xml');
  if (req.method === 'GET' && path === '/oauth/start') {
    const state = await createOAuthState(cfg);
    return redirect(res, oauthAuthorizeUrl(cfg, state));
  }
  if (req.method === 'GET' && path === '/oauth/callback') {
    const state = url.searchParams.get('state') ?? '';
    const code = url.searchParams.get('code') ?? '';
    if (state.length < 32 || code.length < 1 || !await consumeOAuthState(cfg, state)) throw new Error('OAuth state is invalid');
    const tokens = await exchangeCode(cfg, code);
    const account = await vendorUUID(tokens.access);
    if (account !== cfg.allowedAccountUUID) return respond(res, 403, 'This ServiceM8 account is not authorised');
    await saveConnection(cfg, account, tokens);
    return redirect(res, 'https://go.servicem8.com/');
  }
  if (req.method === 'POST' && path === '/events') {
    try {
      const identity = await verifyEvent(await bodyText(req, 16_384));
      const token = await issueSession(identity, 'bc-checker-launch', 300);
      const html = page('Open BC Checker', `<h1>RG BC Checker</h1><p>Open your monitored Job list.</p>
        <form method="post" action="${escape(cfg.baseUrl)}/launch" target="_blank">
        <input type="hidden" name="launch" value="${escape(token)}"><button type="submit">Open BC Checker</button></form>`);
      return respond(res, 200, JSON.stringify({ eventResponse: html }), 'application/json');
    } catch { return respond(res, 401, JSON.stringify({ eventResponse: '<h1>BC Checker launch rejected</h1>' }), 'application/json'); }
  }
  if (req.method === 'POST' && path === '/launch') {
    const params = new URLSearchParams(await bodyText(req, 8_000));
    const launch = params.get('launch') ?? '';
    const identity = await verifySession(launch, 'bc-checker-launch');
    const launchHash = createHash('sha256').update(`launch:${launch}`).digest('hex');
    const consumed = await db.query(`INSERT INTO used_events (event_hash, expires_at)
      VALUES ($1, now() + interval '10 minutes') ON CONFLICT DO NOTHING RETURNING event_hash`, [launchHash]);
    if (consumed.rowCount !== 1) return respond(res, 409, 'This launch link was already used', 'text/plain');
    const token = await issueSession(identity, 'bc-checker-staff', 1800);
    const secure = new URL(cfg.baseUrl).protocol === 'https:' ? '; Secure' : '';
    return redirect(res, '/', { 'Set-Cookie': `bc_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800${secure}` });
  }
  if (req.method === 'GET' && path === '/') return dashboard(req, res);
  if (req.method === 'POST' && path === '/jobs') return addJobs(req, res);
  let match = path.match(/^\/candidates\/([0-9a-f-]{36})\/(ignore|confirm|reopen)$/i);
  if (req.method === 'POST' && match && uuid.test(match[1])) return decision(req, res, match[1],
    { ignore: 'ignored', confirm: 'confirmed', reopen: 'needs_review' }[match[2]]);
  match = path.match(/^\/jobs\/([0-9a-f-]{36})\/stop$/i);
  if (req.method === 'POST' && match && uuid.test(match[1])) return stopJob(req, res, match[1]);
  if (req.method === 'POST' && path === '/cron/check') {
    const supplied = Buffer.from(req.headers.authorization?.replace(/^Bearer /, '') ?? '');
    const expected = Buffer.from(cfg.cronSecret);
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return respond(res, 401, 'Unauthorized');
    const summary = await runDueChecks(cfg);
    return respond(res, 200, JSON.stringify(summary), 'application/json');
  }
  respond(res, 404, 'Not found', 'text/plain');
}

export const requestListener = (req, res) => {
  handle(req, res).catch(error => {
    console.error('BC Checker request failed', { path: req.url, error: error instanceof Error ? error.message : 'Unknown error' });
    if (!res.headersSent) respond(res, 500, 'BC Checker could not complete the request. Please try again.', 'text/plain');
    else res.end();
  });
};
