import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import http from 'node:http';
import { test } from 'node:test';
import { SignJWT } from 'jose';
import { requestListener } from '../src/server.mjs';

test('embedded forms reach their validation and still require a valid CSRF token', async () => {
  Object.assign(process.env, {
    APP_BASE_URL: 'https://bc-checker.example.test',
    SERVICEM8_APP_ID: 'test-app',
    SERVICEM8_APP_SECRET: 'test-secret',
    SERVICEM8_ALLOWED_ACCOUNT_UUID: '11111111-1111-4111-8111-111111111111',
    DATABASE_URL: 'postgres://unused:unused@localhost/unused',
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64'),
    SESSION_SECRET: 'test-session-secret-at-least-32-characters',
    CRON_SECRET: 'test-cron-secret-at-least-32-characters',
  });
  const jti = randomUUID();
  const session = await new SignJWT({
    accountUUID: process.env.SERVICEM8_ALLOWED_ACCOUNT_UUID,
    staffUUID: '22222222-2222-4222-8222-222222222222',
  }).setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer('rg-bc-checker-addon').setAudience('bc-checker-staff')
    .setJti(jti).setIssuedAt().setExpirationTime('5m')
    .sign(new TextEncoder().encode(process.env.SESSION_SECRET));
  const csrf = createHash('sha256').update(`${jti}:${process.env.SESSION_SECRET}`).digest('hex');
  const server = http.createServer(requestListener);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const originalError = console.error;
  const errors = [];
  console.error = (...args) => errors.push(args);
  try {
    const submit = async (origin, form) => {
      const response = await fetch(`${base}/jobs`, { method: 'POST',
        headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ session, jobNumbers: '!', ...form }),
      });
      assert.equal(response.status, 500);
      return errors.pop()?.[1]?.error;
    };
    assert.equal(await submit('null', { csrf }), 'Enter 1–50 valid job numbers');
    assert.equal(await submit('https://go.servicem8.com', { csrf }), 'Enter 1–50 valid job numbers');
    assert.equal(await submit('null', { csrf: 'forged' }), 'Invalid form token');

    const view = await fetch(`${base}/view`, { method: 'POST',
      headers: { Origin: 'null', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ session: 'invalid' }),
    });
    assert.equal(view.status, 401);
  } finally {
    console.error = originalError;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
