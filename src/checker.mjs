import { randomUUID } from 'node:crypto';
import { finishAudit, recordAudit } from './audit.mjs';
import { bcAssessment } from './bc-note.mjs';
import { database } from './db.mjs';
import { classifyEvent, consentIdentity, isIssued, latestConsentEvents, normaliseAddress } from './domain.mjs';
import { lookupConsents } from './homes.mjs';
import { accessToken, getJobByUUID } from './servicem8.mjs';

export async function checkOne(cfg, row, deps = {}) {
  const getToken = deps.accessToken ?? accessToken;
  const getJob = deps.getJobByUUID ?? getJobByUUID;
  const lookup = deps.lookupConsents ?? lookupConsents;
  const db = deps.database ?? database(cfg);
  const token = await getToken(cfg, row.account_uuid);
  const job = await getJob(token, row.job_uuid);
  if (job.uuid !== row.job_uuid || String(job.generated_job_id) !== row.job_number) {
    throw new Error('ServiceM8 job identity changed');
  }
  if (normaliseAddress(job.job_address) !== normaliseAddress(row.job_address)) {
    throw new Error('ServiceM8 job address changed; staff must review it');
  }
  const result = await lookup(job);
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const locked = await client.query('SELECT * FROM monitored_jobs WHERE id=$1 AND status=$2 FOR UPDATE', [row.id, 'active']);
    if (!locked.rows[0]) { await client.query('ROLLBACK'); return { skipped: true }; }
    const firstCheck = !locked.rows[0].baseline_complete;
    let newCandidates = 0;
    for (const event of latestConsentEvents(result.events)) {
      const identity = consentIdentity(event);
      const old = await client.query('SELECT * FROM consent_candidates WHERE monitored_job_id=$1 AND identity_hash=$2 FOR UPDATE', [row.id, identity]);
      const existing = old.rows[0];
      const decision = classifyEvent(event, existing, firstCheck);
      if (!existing) {
        await client.query(`INSERT INTO consent_candidates
          (id, account_uuid, monitored_job_id, identity_hash, consent_number, event_date, action,
           description, source_url, was_issued, decision)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [randomUUID(), row.account_uuid, row.id, identity, event.number, event.date,
          event.action, event.description, result.sourceUrl, isIssued(event), decision]);
        if (decision === 'needs_review') newCandidates++;
      } else {
        await client.query(`UPDATE consent_candidates SET consent_number=$2, event_date=$3,
          action=$4, description=$5, source_url=$6, was_issued=$7, decision=$8,
          last_seen_at=now() WHERE id=$1`,
        [existing.id, event.number, event.date, event.action, event.description,
          result.sourceUrl, existing.was_issued || isIssued(event), decision]);
        if (decision === 'needs_review' && existing.decision !== 'needs_review') newCandidates++;
      }
    }
    await client.query(`UPDATE monitored_jobs SET baseline_complete=true, last_checked_at=now(),
      next_check_at=now() + interval '13 days', last_error=NULL WHERE id=$1`, [row.id]);
    await client.query('COMMIT');
    const assessment = bcAssessment(result.events);
    return { firstCheck, newCandidates, events: result.events.length,
      noteStatus: assessment.status, olderBuildingConsent: assessment.older,
      matchedAddress: result.matchedAddress, sourceUrl: result.sourceUrl };
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

export async function runDueChecks(cfg, options = {}) {
  const db = options.database ?? database(cfg);
  const checker = options.checkOne ?? checkOne;
  const limit = Math.min(Number(options.limit ?? 10), 20);
  const lease = await db.connect();
  const result = [];
  try {
    const lock = await lease.query('SELECT pg_try_advisory_lock(hashtext($1)) AS acquired', ['rg-bc-checker-schedule']);
    if (!lock.rows[0].acquired) return { busy: true, checked: [] };
    await db.query('DELETE FROM oauth_states WHERE expires_at < now()');
    await db.query('DELETE FROM used_events WHERE expires_at < now()');
    const due = await lease.query(`SELECT * FROM monitored_jobs WHERE status='active'
      AND next_check_at <= now() ORDER BY next_check_at, created_at LIMIT $1`, [limit]);
    for (let i = 0; i < due.rows.length; i++) {
      const row = due.rows[i];
      if (i > 0) await new Promise(resolve => setTimeout(resolve, 15_000));
      const auditId = await recordAudit(db, { accountUUID: row.account_uuid, jobUUID: row.job_uuid,
        jobNumber: row.job_number, type: 'scheduled_check', outcome: 'started' });
      try {
        const outcome = await checker(cfg, row);
        await finishAudit(db, auditId, outcome.skipped ? 'skipped' : 'success',
          outcome.skipped ? 'Job no longer monitored' : `${outcome.events} consent events; ${outcome.newCandidates} new candidates`)
          .catch(error => console.error('BC Checker scheduled audit could not be completed', {
            auditId, error: error instanceof Error ? error.message : 'Unknown error',
          }));
        result.push({ jobNumber: row.job_number, ...outcome });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown check error';
        await db.query(`UPDATE monitored_jobs SET last_checked_at=now(),
          next_check_at=now() + interval '6 days', last_error=$2 WHERE id=$1 AND status='active'`,
        [row.id, message.slice(0, 250)]);
        await finishAudit(db, auditId, 'failed', message);
        result.push({ jobNumber: row.job_number, error: message });
      }
    }
    return { busy: false, checked: result };
  } finally {
    await lease.query('SELECT pg_advisory_unlock(hashtext($1))', ['rg-bc-checker-schedule']).catch(() => {});
    lease.release();
  }
}
