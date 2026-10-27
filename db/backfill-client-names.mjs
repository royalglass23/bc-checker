import { config } from '../src/config.mjs';
import { database } from '../src/db.mjs';
import { accessToken, getClientName, getJobByUUID } from '../src/servicem8.mjs';

const cfg = config();
const db = database(cfg);
try {
  const token = await accessToken(cfg, cfg.allowedAccountUUID);
  const result = await db.query(`SELECT id, job_uuid FROM monitored_jobs
    WHERE account_uuid=$1 AND status='active' AND client_name=''`, [cfg.allowedAccountUUID]);
  let updated = 0;
  const failures = [];
  for (const row of result.rows) {
    try {
      const job = await getJobByUUID(token, row.job_uuid);
      const name = await getClientName(token, job.company_uuid);
      if (!name) continue;
      await db.query(`UPDATE monitored_jobs SET client_name=$2
        WHERE id=$1 AND account_uuid=$3 AND client_name=''`, [row.id, name, cfg.allowedAccountUUID]);
      updated++;
    } catch (error) { failures.push({ id: row.id, error: error.message }); }
  }
  console.log(`Client names updated: ${updated}; unresolved: ${result.rows.length - updated}`);
  if (failures.length) {
    console.error(failures);
    process.exitCode = 1;
  }
} finally { await db.end(); }
