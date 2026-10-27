export function config() {
  const required = ['APP_BASE_URL', 'SERVICEM8_APP_ID', 'SERVICEM8_APP_SECRET',
    'SERVICEM8_ALLOWED_ACCOUNT_UUID', 'DATABASE_URL', 'TOKEN_ENCRYPTION_KEY',
    'SESSION_SECRET', 'CRON_SECRET'];
  for (const name of required) if (!process.env[name]) throw new Error(`${name} is required`);
  const base = new URL(process.env.APP_BASE_URL);
  if (base.protocol !== 'https:' && base.hostname !== 'localhost') throw new Error('APP_BASE_URL must use HTTPS');
  const key = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'base64');
  if (key.length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must be 32 bytes in base64');
  if (process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET is too short');
  if (process.env.CRON_SECRET.length < 32) throw new Error('CRON_SECRET is too short');
  return {
    baseUrl: base.toString().replace(/\/$/, ''),
    appId: process.env.SERVICEM8_APP_ID,
    appSecret: process.env.SERVICEM8_APP_SECRET,
    allowedAccountUUID: process.env.SERVICEM8_ALLOWED_ACCOUNT_UUID.toLowerCase(),
    databaseUrl: process.env.DATABASE_URL,
    encryptionKey: key,
    sessionSecret: process.env.SESSION_SECRET,
    cronSecret: process.env.CRON_SECRET,
    port: Number(process.env.PORT || 3000),
  };
}
