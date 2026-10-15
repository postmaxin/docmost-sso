import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeReturnTo } from '../../src/return-to.js';

const app = new URL('https://docs.example.com');

test('accepts same-origin relative paths with query and fragment', () => {
  assert.equal(safeReturnTo('/s/general/p/abc', app), '/s/general/p/abc');
  assert.equal(safeReturnTo('/settings/account?tab=1#x', app), '/settings/account?tab=1#x');
  assert.equal(safeReturnTo('/home', app), '/home');
});

test('rejects absolute, scheme-relative and other-origin URLs', () => {
  for (const bad of [
    'https://evil.com/',
    'https://docs.example.com/home', // absolute, even same origin
    'http://docs.example.com/home',
    '//evil.com',
    '//evil.com/home',
    '///evil.com',
    '/\\evil.com',
    '\\\\evil.com',
    '/\tevil',
    ' /home',
    'javascript:alert(1)',
    'home',
    '',
    '/'.padEnd(3000, 'a'),
  ]) {
    assert.equal(safeReturnTo(bad, app), '/home', JSON.stringify(bad));
  }
});

test('rejects non-strings', () => {
  for (const bad of [undefined, null, 1, ['/x'], { a: 1 }]) {
    assert.equal(safeReturnTo(bad, app), '/home');
  }
});

test('never returns into the sign-in flow', () => {
  for (const loop of ['/sso/login', '/sso/start?redirect=/x', '/sso', '/login', '/login?redirect=/x']) {
    assert.equal(safeReturnTo(loop, app), '/home', loop);
  }
});

test('encoded slashes stay a path on our origin', () => {
  const r = safeReturnTo('/%2F%2Fevil.com', app);
  assert.ok(r.startsWith('/') && !r.startsWith('//'));
  assert.equal(new URL(r, app).origin, app.origin);
});

const front = '/s/general/p/home-iQE6WFhsm6';

test('falls back to the configured front page instead of /home', () => {
  assert.equal(safeReturnTo(undefined, app, front), front);
  assert.equal(safeReturnTo('https://evil.example/x', app, front), front);
});

// Docmost's client sends ?redirect=/home for a signed-out visit to the root,
// which is "no particular destination": send people to the front page instead.
test('treats / and /home as no particular destination', () => {
  for (const generic of ['/', '/home', '/home/']) {
    assert.equal(safeReturnTo(generic, app, front), front, generic);
  }
  assert.equal(safeReturnTo('/home?x=1', app, front), '/home?x=1');
  assert.equal(safeReturnTo('/s/general/p/other-abc', app, front), '/s/general/p/other-abc');
});
