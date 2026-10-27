import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { mergeBcStatus } from './bc-note.mjs';
import manifest from '../public/manifest.json' with { type: 'json' };
import { SignJWT, jwtVerify } from 'jose';
import { config } from './config.mjs';
import { database } from './db.mjs';
import { checkOne, runDueChecks } from './checker.mjs';
import { jobPage, parseJobNumbers } from './domain.mjs';
import { accessToken, addDiaryItem, consumeOAuthState, createOAuthState, exchangeCode,
  getClientName, getJobByNumber, oauthAuthorizeUrl, saveConnection, updateJobNoteField, vendorUUID } from './servicem8.mjs';

let cfg;
let db;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let textKey;

function ensureConfigured() {
  if (cfg) return;
  const value = config();
  cfg = value;
  db = database(value);
  textKey = new TextEncoder().encode(value.sessionSecret);
}

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

async function staff(req, res, params) {
  try { return await verifySession(params?.get('session'), 'bc-checker-staff'); }
  catch { respond(res, 401, '<h1>Session expired</h1><p>Open BC Checker from ServiceM8 again.</p>'); return null; }
}

function csrfFor(identity) {
  return createHash('sha256').update(`${identity.jti}:${cfg.sessionSecret}`).digest('hex');
}

function checkForm(params, identity) {
  // Embedded ServiceM8 forms can arrive with Origin: null. The signed session
  // and its session-bound CSRF token authenticate each state-changing form.
  const given = Buffer.from(params.get('csrf') ?? '');
  const expected = Buffer.from(csrfFor(identity));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new Error('Invalid form token');
}

async function verifyEvent(token) {
  if (!token || token.length > 16_384 || token.split('.').length !== 3) throw new Error('Invalid launch token format');
  const { payload, protectedHeader } = await jwtVerify(token, new TextEncoder().encode(cfg.appSecret),
    { algorithms: ['HS256'], clockTolerance: 30 });
  if (protectedHeader.alg !== 'HS256') throw new Error('Invalid launch algorithm');
  if (payload.eventVersion !== '1.0') throw new Error('Invalid launch event version');
  if (String(payload.eventName).toLowerCase() !== 'rg_bc_checker_menu') throw new Error('Invalid launch event name');
  if (!uuid.test(String(payload.auth?.accountUUID))) throw new Error('Invalid launch account UUID');
  if (!uuid.test(String(payload.auth?.staffUUID))) throw new Error('Invalid launch staff UUID');
  if (String(payload.auth.accountUUID).toLowerCase() !== cfg.allowedAccountUUID) throw new Error('Launch account is not allowed');
  if (!(payload.eventArgs == null ||
      Array.isArray(payload.eventArgs) && payload.eventArgs.length === 0 ||
      payload.eventArgs && typeof payload.eventArgs === 'object' &&
      !Array.isArray(payload.eventArgs) && Object.keys(payload.eventArgs).length === 0)) throw new Error('Invalid launch event arguments');
  if (payload.iat !== undefined && (!Number.isInteger(payload.iat) ||
      Date.now() / 1000 - payload.iat > 300 || payload.iat - Date.now() / 1000 > 30)) {
    throw new Error('Launch event is outside allowed time window');
  }
  // ServiceM8 does not document iat or jti on menu events. A signed event
  // without them may be identical on every legitimate click.
  if (Number.isInteger(payload.iat) && typeof payload.jti === 'string' && payload.jti) {
    const eventHash = createHash('sha256').update(`${payload.auth.accountUUID}:${payload.jti}`).digest('hex');
    const used = await db.query(`INSERT INTO used_events (event_hash, expires_at)
      VALUES ($1, now() + interval '10 minutes') ON CONFLICT DO NOTHING RETURNING event_hash`, [eventHash]);
    if (used.rowCount !== 1) throw new Error('Launch was already used');
  }
  return { accountUUID: String(payload.auth.accountUUID).toLowerCase(),
    staffUUID: String(payload.auth.staffUUID).toLowerCase() };
}

function page(title, body, dashboardScripts = false, embedded = false) {
  const origin = embedded ? cfg.baseUrl : '';
  const policy = embedded ? `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${escape(origin)}; script-src ${escape(origin)}; form-action ${escape(origin)}; base-uri 'none'">` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">${policy}<title>${escape(title)} · RG BC Checker</title><link rel="stylesheet" href="${escape(origin)}/style.css"></head><body><main>${body}</main>${dashboardScripts ? `<script src="${escape(origin)}/xlsx.js" defer></script><script src="${escape(origin)}/app.js" defer></script>` : ''}</body></html>`;
}

function hiddenSession(session) {
  return session ? `<input type="hidden" name="session" value="${escape(session)}">` : '';
}

function actionForm(path, label, csrf, session = '', origin = '') {
  return `<form method="post" action="${escape(origin + path)}"><input type="hidden" name="csrf" value="${csrf}">${hiddenSession(session)}<button type="submit">${escape(label)}</button></form>`;
}

async function renderDashboard(identity, session, query, message, embedded = false) {
  const origin = embedded ? cfg.baseUrl : '';
  const search = String(query.get('search') ?? '').trim().slice(0, 100);
  const term = search.length >= 3 ? search : '';
  const filter = `account_uuid=$1 AND status=$2 AND ($3='' OR
    strpos(lower(job_number), lower($3)) > 0 OR strpos(lower(job_address), lower($3)) > 0 OR
    strpos(lower(client_name), lower($3)) > 0)`;
  const count = await db.query(`SELECT count(*)::int AS total FROM monitored_jobs WHERE ${filter}`,
    [identity.accountUUID, 'active', term]);
  const total = count.rows[0].total;
  const { size: pageSize, pages: pageCount, page: currentPage, offset } = jobPage(
    query.get('size'), query.get('page'), total);
  const jobs = await db.query(`SELECT * FROM monitored_jobs WHERE ${filter}
    ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5`,
    [identity.accountUUID, 'active', term, pageSize, offset]);
  const candidates = await db.query(`SELECT c.* FROM consent_candidates c JOIN monitored_jobs j ON j.id=c.monitored_job_id
    WHERE j.account_uuid=$1 AND j.status='active' AND j.id=ANY($2::uuid[])
    ORDER BY c.first_seen_at DESC`, [identity.accountUUID, jobs.rows.map(job => job.id)]);
  const byJob = Map.groupBy(candidates.rows, row => row.monitored_job_id);
  const csrf = csrfFor(identity);
  const jobViews = jobs.rows.map(job => {
    const rows = byJob.get(job.id) ?? [];
    const review = rows.filter(row => row.decision === 'needs_review').length;
    const renderCandidate = row => `<li class="candidate ${escape(row.decision)}">
      <div><strong>${escape(row.consent_number || 'Number unavailable')}</strong> · ${escape(row.action || 'Status unclear')} · ${escape(row.event_date || 'Date unavailable')}
      <span class="pill">${escape(row.decision.replace('_', ' '))}</span></div>
      ${row.description ? `<p>${escape(row.description)}</p>` : ''}
      <a href="${escape(row.source_url)}" target="_blank" rel="noopener noreferrer">View property source</a>
      <div class="actions">${row.decision === 'ignored'
        ? actionForm(`/candidates/${row.id}/reopen`, 'Reopen for review', csrf, session, origin)
        : `${actionForm(`/candidates/${row.id}/ignore`, 'Wrong BC', csrf, session, origin)}
           ${actionForm(`/candidates/${row.id}/confirm`, 'Right BC — stop checking', csrf, session, origin)}`}</div></li>`;
    const status = review ? `${review} to review` : job.baseline_complete ? 'Monitoring' : 'Waiting for first check';
    const lastChecked = job.last_checked_at
      ? escape(new Date(job.last_checked_at).toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' })) : 'Never';
    return {
      row: `<tr><th scope="row">${escape(job.job_number)}</th><td class="address-cell">${escape(job.job_address)}</td><td>${escape(job.client_name || '—')}</td>
        <td>${lastChecked}${job.last_error ? `<span class="error">Check failed: ${escape(job.last_error)}</span>` : ''}</td>
        <td><span class="pill ${review ? 'attention' : ''}">${status}</span></td>
        <td>${actionForm(`/jobs/${job.id}/check`, 'Check now', csrf, session, origin)}</td>
        <td>${actionForm(`/jobs/${job.id}/stop`, 'Stop monitoring', csrf, session, origin)}</td></tr>`,
      candidates: rows.length ? `<section class="candidate-panel" aria-label="Consent candidates for Job ${escape(job.job_number)}">
        <h3>Consent candidates for Job ${escape(job.job_number)}</h3>
        <ul>${rows.map(renderCandidate).join('')}</ul></section>` : '',
    };
  });
  const flash = message ?? query.get('message');
  const pageControl = (number, label, rel) => session
    ? `<form method="post" action="${escape(origin)}/view"><input type="hidden" name="session" value="${escape(session)}"><input type="hidden" name="search" value="${escape(term)}"><input type="hidden" name="page" value="${number}"><input type="hidden" name="size" value="${pageSize}"><button type="submit">${label}</button></form>`
    : `<a href="/?page=${number}&amp;size=${pageSize}&amp;search=${encodeURIComponent(term)}" rel="${rel}">${label}</a>`;
  return page('Monitored jobs', `<header><p class="eyebrow">Royal Glass · ServiceM8 add-on</p><h1>BC Checker</h1>
    <p>Track Auckland jobs every 14 days. Existing consents form a baseline; only newly seen candidates need review.</p>${session ? '<p>Use the surrounding ServiceM8 navigation to leave BC Checker.</p>' : ''}</header>
    ${flash ? `<p class="flash" role="status">${escape(flash.slice(0, 300))}</p>` : ''}
    <section class="add"><h2>Add jobs to monitor</h2><p>Enter job numbers or upload a CSV or XLSX export. Files can include a Job Number or Generated_Job_ID column.</p>
    <form method="post" action="${escape(origin)}/jobs"><input type="hidden" name="csrf" value="${csrf}">${hiddenSession(session)}
    <div class="add-fields">
      <div class="add-field"><label for="jobNumbers">Job numbers</label><textarea id="jobNumbers" name="jobNumbers" rows="3" maxlength="20000" placeholder="e.g. R123 (one job number per line)" required></textarea></div>
      <div class="add-field"><label for="jobFile">Or upload a list</label><input id="jobFile" type="file" accept=".csv,.xlsx,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" aria-describedby="fileHelp">
      <p id="fileHelp" class="hint">CSV or XLSX · first worksheet · up to 50 jobs at a time</p>
      <p id="fileStatus" class="hint" role="status" aria-live="polite"></p></div>
    </div>
    <button id="addJobsButton" type="submit">Add Job Numbers</button><span id="addJobsStatus" class="submit-status" role="status" aria-live="polite"></span></form></section>
    <section aria-label="Monitored jobs" class="monitored"><div class="list-heading"><div><h2>Monitored jobs</h2><p class="hint">${term ? `${total} matching` : `${total} active`} ${total === 1 ? 'job' : 'jobs'}</p></div>
    <form id="jobSearchForm" class="job-search" method="${session ? 'post' : 'get'}" action="${escape(origin)}${session ? '/view' : '/'}">${hiddenSession(session)}<input type="hidden" name="size" value="${pageSize}"><label for="jobSearch">Search jobs</label><input id="jobSearch" name="search" type="search" minlength="3" maxlength="100" value="${escape(search)}" placeholder="Job number, address or client" autocomplete="off"${term ? ' autofocus' : ''}><button type="submit">Search</button>${term ? '<button id="clearSearch" type="button">Clear</button>' : ''}</form></div>
    ${jobViews.length ? `<div class="table-scroll"><table class="jobs-table"><thead><tr><th scope="col">Job number</th><th scope="col">Address</th><th scope="col">Client</th><th scope="col">Last checked</th><th scope="col">Status</th><th scope="col">Check now</th><th scope="col">Stop monitoring</th></tr></thead><tbody>${jobViews.map(view => view.row).join('')}</tbody></table></div>${jobViews.map(view => view.candidates).join('')}` : `<p class="empty">${term ? `No monitored jobs match “${escape(term)}”.` : 'No jobs are being monitored. Add a job number to start.'}</p>`}
    ${total ? `<nav class="pagination" aria-label="Monitored jobs pages"><span>Showing ${(currentPage - 1) * pageSize + 1}–${Math.min(currentPage * pageSize, total)} of ${total} · Page ${currentPage} of ${pageCount}</span><div>${currentPage > 1 ? pageControl(currentPage - 1, 'Previous', 'prev') : ''}${currentPage < pageCount ? pageControl(currentPage + 1, 'Next', 'next') : ''}</div>
    <form method="${session ? 'post' : 'get'}" action="${escape(origin)}${session ? '/view' : '/'}" class="page-size">${hiddenSession(session)}<input type="hidden" name="search" value="${escape(term)}"><label for="pageSize">Jobs per page</label><select id="pageSize" name="size">${[5, 10, 20, 50].map(size => `<option value="${size}"${size === pageSize ? ' selected' : ''}>${size}</option>`).join('')}</select><button type="submit">Apply</button></form></nav>` : ''}</section>`, true, embedded);
}

async function dashboard(req, res, params, message) {
  const identity = await staff(req, res, params);
  if (!identity) return;
  const query = params ?? new URL(req.url, cfg.baseUrl).searchParams;
  const html = await renderDashboard(identity, params?.get('session') ?? '', query, message);
  respond(res, 200, html, 'text/html; charset=utf-8', {
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors https://*.servicem8.com",
  });
}

async function addJobs(req, res) {
  const params = new URLSearchParams(await bodyText(req, 25_000));
  const identity = await staff(req, res, params);
  if (!identity) return;
  checkForm(params, identity);
  const numbers = parseJobNumbers(params.get('jobNumbers'));
  if (numbers.length === 0 || numbers.length > 50) throw new Error('Enter 1–50 valid job numbers');
  const token = await accessToken(cfg, identity.accountUUID);
  let added = 0;
  const failures = [];
  for (const number of numbers) {
    try {
      const job = await getJobByNumber(token, number);
      if (!uuid.test(job.uuid) || !job.job_address?.trim()) throw new Error('Job has no usable address');
      const clientName = await getClientName(token, job.company_uuid);
      const client = await db.connect();
      try {
        await client.query('BEGIN');
        const result = await client.query(`INSERT INTO monitored_jobs
          (id, account_uuid, job_uuid, job_number, job_address, client_name, job_description, added_by_staff_uuid)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (account_uuid, job_uuid) DO UPDATE SET
          job_number=excluded.job_number, job_address=excluded.job_address,
          client_name=excluded.client_name, job_description=excluded.job_description, status='active', baseline_complete=false,
          last_checked_at=NULL, next_check_at=now(), last_error=NULL,
          added_by_staff_uuid=excluded.added_by_staff_uuid,
          stopped_by_staff_uuid=NULL, stopped_at=NULL
          WHERE monitored_jobs.status='stopped' RETURNING id`,
        [randomUUID(), identity.accountUUID, job.uuid, number, job.job_address, clientName,
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
  if (params.has('session')) return dashboard(req, res, params, message);
  redirect(res, `/?message=${encodeURIComponent(message)}`);
}

async function decision(req, res, candidateId, value) {
  const params = new URLSearchParams(await bodyText(req));
  const identity = await staff(req, res, params);
  if (!identity) return;
  checkForm(params, identity);
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
  if (params.has('session')) return dashboard(req, res, params, message);
  redirect(res, `/?message=${encodeURIComponent(message)}`);
}

async function stopJob(req, res, jobId) {
  const params = new URLSearchParams(await bodyText(req));
  const identity = await staff(req, res, params);
  if (!identity) return;
  checkForm(params, identity);
  await db.query(`UPDATE monitored_jobs SET status='stopped', stopped_by_staff_uuid=$3,
    stopped_at=now() WHERE id=$1 AND account_uuid=$2 AND status='active'`,
  [jobId, identity.accountUUID, identity.staffUUID]);
  if (params.has('session')) return dashboard(req, res, params, 'Job removed from monitoring.');
  redirect(res, '/?message=Job%20removed%20from%20monitoring.');
}

async function checkJobNow(req, res, jobId) {
  const params = new URLSearchParams(await bodyText(req));
  const identity = await staff(req, res, params);
  if (!identity) return;
  checkForm(params, identity);
  const found = await db.query(`SELECT * FROM monitored_jobs WHERE id=$1 AND account_uuid=$2 AND status='active'`,
    [jobId, identity.accountUUID]);
  const job = found.rows[0];
  if (!job) throw new Error('Monitored job is no longer active');
  const connection = await db.query('SELECT scope FROM oauth_connections WHERE account_uuid=$1', [identity.accountUUID]);
  const granted = new Set(String(connection.rows[0]?.scope ?? '').split(/\s+/));
  if (!granted.has('manage_jobs') || !granted.has('publish_diary_items')) {
    const message = 'Reconnect BC Checker in ServiceM8 to enable Job Note field and Diary updates.';
    if (params.has('session')) return dashboard(req, res, params, message);
    return redirect(res, `/?message=${encodeURIComponent(message)}`);
  }
  const lease = await db.connect();
  let message;
  try {
    const lockKey = `bc-checker-manual:${jobId}`;
    const lock = await lease.query('SELECT pg_try_advisory_lock(hashtext($1)) AS acquired', [lockKey]);
    if (!lock.rows[0].acquired) {
      message = 'This address is already being checked. Refresh shortly.';
    } else {
      try {
        const outcome = await checkOne(cfg, job);
        if (outcome.skipped) {
          message = 'This job is no longer being monitored.';
        } else {
          const date = new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' });
          const content = `BC Checker address check — ${date}\nJob ${job.job_number}: ${outcome.matchedAddress || job.job_address}\n${outcome.events} consent event(s) found; ${outcome.firstCheck ? 'first check baseline recorded' : `${outcome.newCandidates} new candidate(s) to review`}. Address results are candidates until staff confirm the right BC.\nSource: ${outcome.sourceUrl}`.slice(0, 1000);
          let noteSaved = false;
          try {
            const token = await accessToken(cfg, identity.accountUUID);
            await updateJobNoteField(token, job.job_uuid, current => mergeBcStatus(current, outcome.noteStatus));
            noteSaved = true;
            await addDiaryItem(token, job.job_uuid, content);
            message = `Address checked. ${outcome.events} consent event(s) found. Note field updated; one Diary entry added.`;
          } catch (error) {
            console.error('BC Checker ServiceM8 update failed', { jobId, noteSaved,
              error: error instanceof Error ? error.message : 'Unknown error' });
            message = `Address checked, but ServiceM8 ${noteSaved ? 'Diary' : 'Note field'} update failed. Do not click again until the job is reviewed.`;
          }
        }
      } catch (error) {
        const detail = error instanceof Error ? error.message : 'Unknown check error';
        await db.query(`UPDATE monitored_jobs SET last_error=$2 WHERE id=$1 AND account_uuid=$3 AND status='active'`,
          [jobId, detail.slice(0, 250), identity.accountUUID]);
        message = `Address check failed: ${detail}`;
      } finally {
        await lease.query('SELECT pg_advisory_unlock(hashtext($1))', [lockKey]).catch(() => {});
      }
    }
  } finally { lease.release(); }
  if (params.has('session')) return dashboard(req, res, params, message);
  redirect(res, `/?message=${encodeURIComponent(message)}`);
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  if (req.method === 'GET' && path === '/health') return respond(res, 200, 'ok', 'text/plain');
  if (req.method === 'GET' && path === '/manifest.json') return respond(res, 200, JSON.stringify(manifest), 'application/json');
  if (req.method === 'GET' && path === '/style.css') return respond(res, 200, await readFile(new URL('./style.css', import.meta.url)), 'text/css');
  if (req.method === 'GET' && path === '/app.js') return respond(res, 200, await readFile(new URL('./app.js', import.meta.url)), 'text/javascript');
  if (req.method === 'GET' && path === '/xlsx.js') return respond(res, 200,
    await readFile(new URL('../public/xlsx.js', import.meta.url)), 'text/javascript');
  if (req.method === 'GET' && path === '/icon.png') return respond(res, 200, await readFile(new URL('../public/icon.png', import.meta.url)), 'image/png');
  if (req.method === 'GET' && path === '/icon.svg') return respond(res, 200, await readFile(new URL('./icon.svg', import.meta.url)), 'image/svg+xml');
  ensureConfigured();
  if (req.method === 'GET' && path === '/oauth/start') {
    const state = await createOAuthState(cfg);
    return redirect(res, oauthAuthorizeUrl(cfg, state));
  }
  if (req.method === 'GET' && path === '/oauth/callback') {
    const state = url.searchParams.get('state') ?? '';
    const code = url.searchParams.get('code') ?? '';
    let stage = 'validate_state';
    try {
      if (state.length < 32 || !await consumeOAuthState(cfg, state)) throw new Error('OAuth state is invalid');
      stage = 'oauth_response';
      if (url.searchParams.has('error')) {
        const reason = url.searchParams.get('error');
        console.warn('BC Checker OAuth access denied', { reason: reason === 'access_denied' ? reason : 'other' });
        return respond(res, reason === 'access_denied' ? 403 : 400,
          reason === 'access_denied' ? 'BC Checker access was not granted in ServiceM8.' : 'BC Checker authorisation failed in ServiceM8.');
      }
      if (!code) throw new Error('OAuth code is missing');
      stage = 'exchange_code';
      const tokens = await exchangeCode(cfg, code);
      stage = 'verify_account';
      const account = await vendorUUID(tokens.access);
      if (account !== cfg.allowedAccountUUID) return respond(res, 403, 'This ServiceM8 account is not authorised');
      stage = 'save_connection';
      await saveConnection(cfg, account, tokens);
      return redirect(res, 'https://go.servicem8.com/');
    } catch (error) {
      console.error('BC Checker OAuth callback failed', { stage,
        error: error instanceof Error ? error.message : 'Unknown error' });
      return respond(res, stage === 'validate_state' || stage === 'oauth_response' ? 400 : 500,
        'BC Checker could not complete authorisation. Please try again.');
    }
  }
  if (req.method === 'POST' && path === '/events') {
    let stage = 'verify_event';
    try {
      const identity = await verifyEvent(await bodyText(req, 16_384));
      stage = 'issue_session';
      const session = await issueSession(identity, 'bc-checker-staff', 1800);
      const staffIdentity = await verifySession(session, 'bc-checker-staff');
      stage = 'render_dashboard';
      const html = await renderDashboard(staffIdentity, session, new URLSearchParams(), null, true);
      return respond(res, 200, JSON.stringify({ eventResponse: html }), 'application/json');
    } catch (error) {
      console.error('BC Checker launch failed', { stage,
        error: error instanceof Error ? error.message : 'Unknown error' });
      return respond(res, 401, JSON.stringify({ eventResponse: '<h1>BC Checker launch rejected</h1>' }), 'application/json');
    }
  }
  if (req.method === 'POST' && path === '/view') {
    const params = new URLSearchParams(await bodyText(req, 8_000));
    return dashboard(req, res, params);
  }
  if (req.method === 'GET' && path === '/') return dashboard(req, res);
  if (req.method === 'POST' && path === '/jobs') return addJobs(req, res);
  let match = path.match(/^\/candidates\/([0-9a-f-]{36})\/(ignore|confirm|reopen)$/i);
  if (req.method === 'POST' && match && uuid.test(match[1])) return decision(req, res, match[1],
    { ignore: 'ignored', confirm: 'confirmed', reopen: 'needs_review' }[match[2]]);
  match = path.match(/^\/jobs\/([0-9a-f-]{36})\/check$/i);
  if (req.method === 'POST' && match && uuid.test(match[1])) return checkJobNow(req, res, match[1]);
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
    console.error('BC Checker request failed', { path: new URL(req.url, 'http://localhost').pathname,
      error: error instanceof Error ? error.message : 'Unknown error' });
    if (!res.headersSent) respond(res, 500, 'BC Checker could not complete the request. Please try again.', 'text/plain');
    else res.end();
  });
};
