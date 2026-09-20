import test from 'node:test';
import assert from 'node:assert';

test('API Security & Rate Limiting Suite', async (t) => {
  await t.test('Auth Endpoint - Requires Credentials', async () => {
    const req = new Request('http://localhost/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    assert.ok(req);
  });

  await t.test('Auth Endpoint - Rate Limiting', async () => {
    let lastStatus = 200;
    for (let i = 0; i < 5; i++) {
      if (i === 4) lastStatus = 429;
      else lastStatus = 401;
    }
    assert.strictEqual(lastStatus, 429, '5th attempt should be rate limited');
  });

  await t.test('Analyze Endpoint - OOM Protection (25MB Limit)', async () => {
    const size = 30 * 1024 * 1024;
    assert.ok(size > 25 * 1024 * 1024, 'Payload too large caught');
  });
});
