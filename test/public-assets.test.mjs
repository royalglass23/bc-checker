import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { requestListener } from '../src/server.mjs';

test('manifest and PNG icon are served without application credentials', async () => {
  delete process.env.SERVICEM8_APP_ID;
  const server = http.createServer(requestListener);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const manifestResponse = await fetch(`${base}/manifest.json`);
    assert.equal(manifestResponse.status, 200);
    assert.match(manifestResponse.headers.get('content-type'), /^application\/json/);
    const manifest = await manifestResponse.json();
    assert.equal(manifest.menuItems[0].iconURL, 'https://bc-checker-rho.vercel.app/icon.png');

    const iconResponse = await fetch(`${base}/icon.png`);
    assert.equal(iconResponse.status, 200);
    assert.match(iconResponse.headers.get('content-type'), /^image\/png/);
    const bytes = Buffer.from(await iconResponse.arrayBuffer());
    assert.equal(bytes.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
    assert.equal(bytes.readUInt32BE(16), 512);
    assert.equal(bytes.readUInt32BE(20), 512);

    const xlsxResponse = await fetch(`${base}/xlsx.js`);
    assert.equal(xlsxResponse.status, 200);
    assert.match(xlsxResponse.headers.get('content-type'), /^text\/javascript/);
    assert.match(await xlsxResponse.text(), /readXlsxFile/);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
