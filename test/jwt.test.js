import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeBase64Url, parseJwt, lint, humanTime } from '../jwt.js';

const token = (header, payload, signature = 'signature') => `${encodeBase64Url(JSON.stringify(header))}.${encodeBase64Url(JSON.stringify(payload))}.${signature}`;

test('parses a compact signed JWT', () => {
  const parsed = parseJwt(token({ alg: 'HS256', typ: 'JWT' }, { sub: 'dev', exp: 2000000000 }));
  assert.equal(parsed.type, 'JWS'); assert.equal(parsed.header.alg, 'HS256'); assert.equal(parsed.payload.sub, 'dev');
});
test('recognizes a JWE without attempting payload decoding', () => assert.equal(parseJwt('a.b.c.d.e').type, 'JWE'));
test('rejects malformed compact tokens', () => assert.throws(() => parseJwt('a.b'), /three/));
test('flags unsafe algorithm, expiry, and sensitive payload values', () => {
  const findings = lint({ alg: 'none' }, { password: 'not-safe', exp: 1 }, 100000);
  assert(findings.some(f => f.title === 'Unsigned token'));
  assert(findings.some(f => f.title === 'Token expired'));
  assert(findings.some(f => f.title === 'Possible sensitive data in payload'));
});
test('humanizes NumericDate timestamps', () => {
  const value = humanTime(1001, 1000000);
  assert.match(value.relative, /Expires in 1 second/); assert.match(value.iso, /^1970-01-01T00:16:41/);
});
