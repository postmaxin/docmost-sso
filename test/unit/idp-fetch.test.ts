import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isNetworkFailure, isNotSent, retryingFetch } from '../../src/idp-fetch.js';

function fetchFailed(code: string): TypeError {
  return new TypeError('fetch failed', { cause: Object.assign(new Error(code), { code }) });
}

/** A fake fetch that fails with each error in turn, then succeeds. */
function flaky(errors: unknown[]) {
  const calls: { url: string; options: { body: string } }[] = [];
  const inner = async (url: string, options: { body: string }) => {
    calls.push({ url, options });
    const err = errors.shift();
    if (err !== undefined) throw err;
    return new Response('ok');
  };
  return { inner, calls };
}

test('only failures before the request is sent count as not sent', () => {
  for (const code of ['UND_ERR_CONNECT_TIMEOUT', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EAI_AGAIN']) {
    assert.equal(isNotSent(fetchFailed(code)), true, code);
  }
  // The request may have reached the IdP: never retried.
  for (const code of ['ECONNRESET', 'UND_ERR_SOCKET', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT']) {
    assert.equal(isNotSent(fetchFailed(code)), false, code);
    assert.equal(isNetworkFailure(fetchFailed(code)), true, code);
  }
  assert.equal(isNotSent(new TypeError('fetch failed')), false);
  assert.equal(isNotSent(new Error('x', { cause: { code: 'ECONNREFUSED' } })), false);
  assert.equal(isNetworkFailure(new Error('unexpected ID Token "nonce" claim value')), false);
});

test('retries a connection that never opened, with the same request', async () => {
  const { inner, calls } = flaky([fetchFailed('UND_ERR_CONNECT_TIMEOUT'), fetchFailed('ECONNREFUSED')]);
  const res = await retryingFetch(3, inner)('https://idp.example/token', { body: 'code=abc' });
  assert.equal(await res.text(), 'ok');
  assert.equal(calls.length, 3);
  assert.ok(calls.every((c) => c.url === 'https://idp.example/token' && c.options.body === 'code=abc'));
});

test('gives up after the last attempt', async () => {
  const last = fetchFailed('UND_ERR_CONNECT_TIMEOUT');
  const { inner, calls } = flaky([fetchFailed('UND_ERR_CONNECT_TIMEOUT'), fetchFailed('UND_ERR_CONNECT_TIMEOUT'), last]);
  await assert.rejects(retryingFetch(3, inner)('https://idp.example/token', { body: '' }), (err) => err === last);
  assert.equal(calls.length, 3);
});

test('does not retry once the request may have been sent', async () => {
  const reset = fetchFailed('ECONNRESET');
  const { inner, calls } = flaky([reset]);
  await assert.rejects(retryingFetch(3, inner)('https://idp.example/token', { body: '' }), (err) => err === reset);
  assert.equal(calls.length, 1);
});
