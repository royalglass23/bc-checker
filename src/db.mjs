import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import pg from 'pg';

let pool;
export function database(cfg) {
  pool ??= new pg.Pool({ connectionString: cfg.databaseUrl, max: 5 });
  return pool;
}

export function seal(text, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
}

export function unseal(value, key) {
  const raw = Buffer.from(value, 'base64');
  if (raw.length < 29) throw new Error('Encrypted token is invalid');
  const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}
