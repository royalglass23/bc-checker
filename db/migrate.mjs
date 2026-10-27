import { readFile } from 'node:fs/promises';
import pg from 'pg';

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const db = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await db.connect();
  await db.query(await readFile(new URL('./schema.sql', import.meta.url), 'utf8'));
  console.log('BC Checker schema applied');
} finally { await db.end(); }
