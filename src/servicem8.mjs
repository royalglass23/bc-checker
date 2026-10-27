import { createHash, randomBytes } from 'node:crypto';
import { database, seal, unseal } from './db.mjs';

const api = 'https://api.servicem8.com/api_1.0';
const tokenUrl = 'https://go.servicem8.com/oauth/access_token';
export const scopes = 'vendor read_jobs publish_job_notes publish_diary_items';
const readScopes = ['vendor', 'read_jobs'];

export function oauthAuthorizeUrl(cfg, state) {
  const url = new URL('https://go.servicem8.com/oauth/authorize');
  url.search = new URLSearchParams({ response_type: 'code', client_id: cfg.appId,
    scope: scopes, redirect_uri: `${cfg.baseUrl}/oauth/callback`, state }).toString();
  return url.toString();
}

export async function createOAuthState(cfg) {
  const state = randomBytes(32).toString('base64url');
  const hash = createHash('sha256').update(state).digest('hex');
  await database(cfg).query('INSERT INTO oauth_states (state_hash, expires_at) VALUES ($1, now() + interval \'10 minutes\')', [hash]);
  return state;
}

export async function consumeOAuthState(cfg, state) {
  const hash = createHash('sha256').update(state).digest('hex');
  const result = await database(cfg).query('DELETE FROM oauth_states WHERE state_hash = $1 AND expires_at > now() RETURNING state_hash', [hash]);
  return result.rowCount === 1;
}

async function tokenRequest(cfg, body) {
  const response = await fetch(tokenUrl, { method: 'POST', headers: {
    'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
  }, body: new URLSearchParams(body), signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`ServiceM8 OAuth returned ${response.status}`);
  const data = await response.json();
  if (!data.access_token || !data.refresh_token || !Number.isFinite(Number(data.expires_in))) {
    throw new Error('ServiceM8 OAuth response is incomplete');
  }
  const granted = new Set(String(data.scope ?? '').split(/\s+/));
  if (readScopes.some(scope => !granted.has(scope))) throw new Error('ServiceM8 permissions are incomplete');
  return { access: data.access_token, refresh: data.refresh_token,
    expires: new Date(Date.now() + Number(data.expires_in) * 1000), scope: data.scope };
}

export async function exchangeCode(cfg, code) {
  return tokenRequest(cfg, { grant_type: 'authorization_code', client_id: cfg.appId,
    client_secret: cfg.appSecret, redirect_uri: `${cfg.baseUrl}/oauth/callback`, code });
}

async function refreshToken(cfg, refresh) {
  return tokenRequest(cfg, { grant_type: 'refresh_token', client_id: cfg.appId,
    client_secret: cfg.appSecret, refresh_token: refresh });
}

export async function saveConnection(cfg, accountUUID, tokens) {
  await database(cfg).query(`INSERT INTO oauth_connections
    (account_uuid, access_token_ciphertext, refresh_token_ciphertext, expires_at, scope)
    VALUES ($1,$2,$3,$4,$5) ON CONFLICT (account_uuid) DO UPDATE SET
    access_token_ciphertext=excluded.access_token_ciphertext,
    refresh_token_ciphertext=excluded.refresh_token_ciphertext,
    expires_at=excluded.expires_at, scope=excluded.scope, updated_at=now()`,
  [accountUUID, seal(tokens.access, cfg.encryptionKey), seal(tokens.refresh, cfg.encryptionKey), tokens.expires, tokens.scope]);
}

export async function accessToken(cfg, accountUUID) {
  const client = await database(cfg).connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`bc-checker:${accountUUID}`]);
    const result = await client.query('SELECT * FROM oauth_connections WHERE account_uuid=$1 FOR UPDATE', [accountUUID]);
    const row = result.rows[0];
    if (!row) throw new Error('ServiceM8 add-on has not been activated');
    if (new Date(row.expires_at).getTime() > Date.now() + 60_000) {
      await client.query('COMMIT');
      return unseal(row.access_token_ciphertext, cfg.encryptionKey);
    }
    const tokens = await refreshToken(cfg, unseal(row.refresh_token_ciphertext, cfg.encryptionKey));
    await client.query(`UPDATE oauth_connections SET access_token_ciphertext=$2,
      refresh_token_ciphertext=$3, expires_at=$4, scope=$5, updated_at=now() WHERE account_uuid=$1`,
    [accountUUID, seal(tokens.access, cfg.encryptionKey), seal(tokens.refresh, cfg.encryptionKey), tokens.expires, tokens.scope]);
    await client.query('COMMIT');
    return tokens.access;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}

export async function serviceM8Get(token, path) {
  const response = await fetch(`${api}${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`ServiceM8 returned ${response.status}`);
  return response.json();
}

async function serviceM8Post(token, path, body) {
  const response = await fetch(`${api}${path}`, { method: 'POST', headers: {
    Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json',
  }, body: JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`ServiceM8 write returned ${response.status}`);
  return response;
}

export async function addJobNote(token, jobUUID, note) {
  return serviceM8Post(token, '/note.json', { related_object: 'job', related_object_uuid: jobUUID, note });
}

export async function addDiaryItem(token, jobUUID, content) {
  if (content.length > 1000) throw new Error('Diary item is too long');
  return serviceM8Post(token, '/diary.json', { job_uuid: jobUUID, content });
}

export async function vendorUUID(token) {
  const vendors = await serviceM8Get(token, '/vendor.json');
  const uuid = Array.isArray(vendors) && vendors.length === 1 ? vendors[0]?.uuid : null;
  if (typeof uuid !== 'string') throw new Error('ServiceM8 Vendor ID is unavailable');
  return uuid.toLowerCase();
}

export async function getJobByNumber(token, number) {
  const filter = `generated_job_id eq '${number.replaceAll("'", "''")}'`;
  const jobs = await serviceM8Get(token, `/job.json?$filter=${encodeURIComponent(filter)}`);
  if (!Array.isArray(jobs) || jobs.length !== 1 || String(jobs[0].generated_job_id) !== number) {
    throw new Error(`Job ${number} was not uniquely found`);
  }
  return jobs[0];
}

export async function getJobByUUID(token, uuid) {
  return serviceM8Get(token, `/job/${encodeURIComponent(uuid)}.json`);
}
