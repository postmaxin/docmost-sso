import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clientIp } from '../../src/client-ip.js';

test('bare IPv4 and IPv6 addresses pass through', () => {
  assert.equal(clientIp('141.193.149.247'), '141.193.149.247');
  assert.equal(clientIp('2001:db8::1'), '2001:db8::1');
});

// AWS ALBs with routing.http.xff_client_port.enabled append the client port
// to the X-Forwarded-For entry they add, which then becomes req.ip.
test('strips the port an ALB appends to an IPv4 X-Forwarded-For entry', () => {
  assert.equal(clientIp('141.193.149.247:54321'), '141.193.149.247');
});

test('strips the port from a bracketed IPv6 entry', () => {
  assert.equal(clientIp('[2001:db8::1]:443'), '2001:db8::1');
  assert.equal(clientIp('[2001:db8::1]'), '2001:db8::1');
});

test('anything that is not an address (with an optional port) is null', () => {
  for (const bad of [undefined, '', 'unknown', 'example.com:80', '1.2.3:80', '1.2.3.4:', '1.2.3.4:99999x', '[not-ip]:1', '1.2.3.4 , 5.6.7.8']) {
    assert.equal(clientIp(bad), null, String(bad));
  }
});
