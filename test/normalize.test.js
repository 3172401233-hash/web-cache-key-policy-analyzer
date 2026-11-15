import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizePath,
  normalizeHost,
  parseQuery,
  canonicalizeQuery,
  parseCookies,
  removeDotSegments,
  decodeUnreserved,
} from '../src/normalize.js';

test('dot-segment paths normalize per RFC 3986', () => {
  assert.equal(removeDotSegments('/a/b/c/./../../g'), '/a/g');
  assert.equal(removeDotSegments('/mid/content=5/../6'), '/mid/6');
  assert.equal(normalizePath('/account/../admin/panel'), '/admin/panel');
  assert.equal(normalizePath('/a/./b'), '/a/b');
  assert.equal(normalizePath('/a/..'), '/');
});

test('double slashes collapse to single slashes', () => {
  assert.equal(normalizePath('//a//b///c'), '/a/b/c');
  assert.equal(normalizePath('/a//'), '/a/');
});

test('path case sensitivity is configurable', () => {
  assert.equal(normalizePath('/Admin/Panel'), '/Admin/Panel');
  assert.equal(
    normalizePath('/Admin/Panel', { caseSensitive: false }),
    '/admin/panel',
  );
});

test('unreserved percent-encodings decode, reserved ones survive', () => {
  assert.equal(decodeUnreserved('/%7Euser/%61dmin'), '/~user/admin');
  assert.equal(decodeUnreserved('/a%2fb'), '/a%2Fb');
  assert.equal(normalizePath('/%7Ealice'), '/~alice');
  assert.notEqual(normalizePath('/a%2Fb'), '/a/b');
});

test('duplicate query parameters are preserved in order', () => {
  const pairs = parseQuery('a=1&a=2&b=3');
  assert.deepEqual(pairs, [['a', '1'], ['a', '2'], ['b', '3']]);
});

test('canonicalizeQuery sorts but keeps duplicate relative order', () => {
  const pairs = parseQuery('b=1&a=2&a=1');
  assert.deepEqual(canonicalizeQuery(pairs), [['a', '2'], ['a', '1'], ['b', '1']]);
});

test('canonicalizeQuery drops ignored params case-insensitively', () => {
  const pairs = parseQuery('Token=abc&page=2');
  assert.deepEqual(canonicalizeQuery(pairs, { ignore: ['token'] }), [['page', '2']]);
});

test('multi-value cookies keep every value', () => {
  const jar = parseCookies('session=aaa; theme=dark; session=bbb');
  assert.deepEqual(jar.get('session'), ['aaa', 'bbb']);
  assert.deepEqual(jar.get('theme'), ['dark']);
});

test('host normalization lowercases and strips default ports', () => {
  assert.equal(normalizeHost('EXAMPLE.com'), 'example.com');
  assert.equal(normalizeHost('example.com:443'), 'example.com');
  assert.equal(normalizeHost('example.com:8443'), 'example.com:8443');
});
