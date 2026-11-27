import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Oidc } from '../../src/oidc.js';

test('IdP requests go through the retrying fetch (discovery survives refused connects)', async () => {
  const server = createServer((req, res) => {
    const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        issuer,
        authorization_endpoint: `${issuer}authorize`,
        token_endpoint: `${issuer}token`,
        jwks_uri: `${issuer}jwks`,
        response_types_supported: ['code'],
      }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;

  const realFetch = globalThis.fetch;
  let refusals = 2;
  let calls = 0;
  globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
    calls++;
    if (refusals-- > 0) {
      throw new TypeError('fetch failed', { cause: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) });
    }
    return realFetch(...args);
  }) as typeof fetch;
  try {
    const oidc = new Oidc({
      issuer,
      clientId: 'cid',
      clientSecret: 'secret',
      redirectUri: 'https://docs.example.com/sso/callback',
      allowInsecure: true,
      allowedDomains: ['*'],
    });
    const { url } = await oidc.begin('/home');
    assert.equal(url.origin + url.pathname, `${issuer}authorize`);
    assert.equal(calls, 3);
  } finally {
    globalThis.fetch = realFetch;
    server.close();
  }
});
