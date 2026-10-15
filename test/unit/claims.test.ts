import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkClaims, GOOGLE_ISSUER, refusalMessage } from '../../src/claims.js';

const allowed = ['example.com'];
const generic = 'https://idp.example.com';

test('admits a verified address in an allowed domain (non-Google issuer, no hd)', () => {
  const r = checkClaims({ iss: generic, email: 'Alice@Example.COM', email_verified: true, name: 'Alice' }, allowed);
  assert.deepEqual(r, { ok: true, email: 'alice@example.com', name: 'Alice' });
});

test('refuses an unverified email', () => {
  for (const email_verified of [false, undefined, 'true', 1, null]) {
    const r = checkClaims({ iss: generic, email: 'a@example.com', email_verified }, allowed);
    assert.equal(r.ok, false);
    assert.equal(!r.ok && r.reason, 'email_not_verified', `email_verified=${String(email_verified)}`);
  }
});

test('refuses a missing or malformed email', () => {
  for (const email of [undefined, '', 42, 'no-at-sign', 'a@b@example.com', 'a b@example.com', 'a@example.com\n']) {
    const r = checkClaims({ iss: generic, email, email_verified: true }, allowed);
    assert.equal(!r.ok && r.reason, 'missing_email', `email=${JSON.stringify(email)}`);
  }
});

test('refuses a wrong domain, including look-alikes and subdomains', () => {
  for (const email of [
    'a@gmail.com',
    'a@example.com.evil.com',
    'a@evilexample.com',
    'a@sub.example.com',
    'a@example.com.',
  ]) {
    const r = checkClaims({ iss: generic, email, email_verified: true }, allowed);
    assert.equal(r.ok, false, email);
  }
  const r = checkClaims({ iss: generic, email: 'a@gmail.com', email_verified: true }, allowed);
  assert.equal(!r.ok && r.reason, 'domain_not_allowed');
});

test('Google issuer: requires hd in the allowed list', () => {
  const base = { iss: GOOGLE_ISSUER, email: 'a@example.com', email_verified: true };
  assert.equal(checkClaims({ ...base, hd: 'example.com' }, allowed).ok, true);
  assert.equal(checkClaims({ ...base, hd: 'EXAMPLE.COM' }, allowed).ok, true);
  for (const hd of [undefined, '', 'gmail.com', 'other.com', 7]) {
    const r = checkClaims({ ...base, hd }, allowed);
    assert.equal(!r.ok && r.reason, 'hd_mismatch', `hd=${String(hd)}`);
  }
  // Legacy issuer spelling Google documents as valid.
  const legacy = checkClaims({ ...base, iss: 'accounts.google.com' }, allowed);
  assert.equal(!legacy.ok && legacy.reason, 'hd_mismatch');
});

test('any issuer: an hd claim, when present, must be allowed', () => {
  const r = checkClaims({ iss: generic, email: 'a@example.com', email_verified: true, hd: 'other.com' }, allowed);
  assert.equal(!r.ok && r.reason, 'hd_mismatch');
});

test('name: sanitised, capped, falls back to undefined', () => {
  const r = checkClaims({ iss: generic, email: 'a@example.com', email_verified: true, name: ` Bob\u0007 ${'x'.repeat(80)}` }, allowed);
  assert.ok(r.ok);
  assert.equal(r.ok && r.name!.length, 50);
  assert.ok(r.ok && !r.name!.includes('\u0007'));
  const n = checkClaims({ iss: generic, email: 'a@example.com', email_verified: true, name: '  ' }, allowed);
  assert.equal(n.ok && n.name, undefined);
});

test('refusal message names the allowed domains', () => {
  assert.equal(refusalMessage('domain_not_allowed', ['example.com']), 'Only @example.com accounts can sign in here.');
});
