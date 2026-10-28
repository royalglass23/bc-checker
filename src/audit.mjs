import { randomUUID } from 'node:crypto';

export async function recordAudit(client, event) {
  const id = randomUUID();
  await client.query(`INSERT INTO checker_audit_events
    (id, account_uuid, job_uuid, job_number, event_type, staff_uuid, staff_name, outcome, detail, completed_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $8='started' THEN NULL ELSE now() END)`,
  [id, event.accountUUID, event.jobUUID ?? null, event.jobNumber ?? '', event.type,
    event.staffUUID ?? null, String(event.staffName ?? '').slice(0, 80), event.outcome,
    String(event.detail ?? '').slice(0, 300)]);
  return id;
}

export async function finishAudit(client, id, outcome, detail = '') {
  await client.query(`UPDATE checker_audit_events SET outcome=$2, detail=$3, completed_at=now()
    WHERE id=$1 AND outcome='started'`, [id, outcome, String(detail).slice(0, 300)]);
}
