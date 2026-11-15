import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditIsolation, isSharedCacheable } from '../src/audit.js';
import { computeCacheKey, effectiveVary, mergePolicy } from '../src/cacheKey.js';

const PROTECTED_ORIGIN = {
  protected: true,
  cacheControl: 'public, max-age=300',
  vary: [],
};

function req(overrides) {
  return {
    id: 'r1',
    user: 'alice',
    host: 'example.com',
    path: '/account',
    query: '',
    cookie: '',
    headers: {},
    ...overrides,
  };
}

function findingCodes(result) {
  return result.findings.map((f) => f.code);
}

test('protected + cacheable resource is flagged', () => {
  const result = auditIsolation({ requests: [req({})], origin: PROTECTED_ORIGIN });
  assert.ok(findingCodes(result).includes('PROTECTED_RESOURCE_CACHEABLE'));
});

test('private/no-store responses are not shared-cacheable', () => {
  assert.equal(isSharedCacheable('private, max-age=300'), false);
  assert.equal(isSharedCacheable('no-store'), false);
  assert.equal(isSharedCacheable('public, max-age=300'), true);
  assert.equal(isSharedCacheable('s-maxage=60'), true);
});

test('two users, no auth in key: cross-user cache hit with canonical key', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice', cookie: 'session=alice-token' }),
      req({ id: 'b', user: 'bob', cookie: 'session=bob-token' }),
    ],
    origin: PROTECTED_ORIGIN,
    cdn: { cookies: [] },
  });
  const codes = findingCodes(result);
  assert.ok(codes.includes('CROSS_USER_CACHE_HIT'));
  assert.ok(codes.includes('SENSITIVE_COOKIE_MISSING'));
  assert.equal(result.conflicts.length, 1);
  const conflict = result.conflicts[0];
  assert.deepEqual(conflict.users, ['alice', 'bob']);
  // The canonical key contains no cookie material: both users share it.
  assert.ok(conflict.key.includes('path=/account'));
  assert.ok(!conflict.key.includes('alice-token'));
  assert.ok(!conflict.key.includes('bob-token'));
});

test('keying the session cookie separates users', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice', cookie: 'session=alice-token' }),
      req({ id: 'b', user: 'bob', cookie: 'session=bob-token' }),
    ],
    origin: PROTECTED_ORIGIN,
    cdn: { cookies: ['session'] },
  });
  assert.equal(result.conflicts.length, 0);
  assert.ok(!findingCodes(result).includes('CROSS_USER_CACHE_HIT'));
});

test('authorization header missing from key is critical', () => {
  const result = auditIsolation({
    requests: [
      req({
        id: 'a',
        user: 'alice',
        headers: { authorization: 'Bearer aaa' },
      }),
      req({ id: 'b', user: 'bob', headers: { authorization: 'Bearer bbb' } }),
    ],
    origin: PROTECTED_ORIGIN,
  });
  const codes = findingCodes(result);
  assert.ok(codes.includes('AUTH_CONTEXT_MISSING'));
  assert.ok(codes.includes('CROSS_USER_CACHE_HIT'));
});

test('origin Vary: Authorization honored by default prevents collision', () => {
  const result = auditIsolation({
    requests: [
      req({
        id: 'a',
        user: 'alice',
        headers: { authorization: 'Bearer aaa' },
      }),
      req({ id: 'b', user: 'bob', headers: { authorization: 'Bearer bbb' } }),
    ],
    origin: { ...PROTECTED_ORIGIN, vary: ['Authorization'] },
  });
  assert.equal(result.conflicts.length, 0);
});

test('CDN Vary override that drops origin entries is a merge error', () => {
  const result = auditIsolation({
    requests: [
      req({
        id: 'a',
        user: 'alice',
        headers: { authorization: 'Bearer aaa' },
      }),
      req({ id: 'b', user: 'bob', headers: { authorization: 'Bearer bbb' } }),
    ],
    origin: { ...PROTECTED_ORIGIN, vary: ['Authorization'] },
    cdn: { varyHandling: 'override', varyOverride: ['Accept-Encoding'] },
  });
  const codes = findingCodes(result);
  assert.ok(codes.includes('VARY_MERGE_ERROR'));
  assert.ok(codes.includes('CROSS_USER_CACHE_HIT'));
});

test('CDN ignoring origin Vary is reported', () => {
  const result = auditIsolation({
    requests: [req({})],
    origin: { ...PROTECTED_ORIGIN, vary: ['Cookie'] },
    cdn: { varyHandling: 'ignore' },
  });
  assert.ok(findingCodes(result).includes('VARY_MERGE_ERROR'));
  assert.deepEqual(effectiveVary(['Cookie'], mergePolicy({ varyHandling: 'ignore' })), []);
});

test('Vary merge unions origin vary with CDN headers', () => {
  const policy = mergePolicy({
    varyHandling: 'merge',
    headers: ['x-tenant'],
  });
  assert.deepEqual(effectiveVary(['Cookie'], policy), ['cookie', 'x-tenant']);
});

test('dot-segment and double-slash variants of one path collide', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice', path: '/account' }),
      req({ id: 'b', user: 'bob', path: '/x/../account' }),
      req({ id: 'c', user: 'carol', path: '//account' }),
    ],
    origin: PROTECTED_ORIGIN,
  });
  assert.ok(findingCodes(result).includes('PATH_ENCODING_INCONSISTENCY'));
  // All three normalize to /account, so every cross-user pair conflicts.
  assert.equal(result.conflicts.length, 3);
  assert.ok(result.conflicts[0].key.includes('path=/account'));
});

test('case-insensitive CDN path handling collides /Admin and /admin', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice', path: '/Admin' }),
      req({ id: 'b', user: 'bob', path: '/admin' }),
    ],
    origin: PROTECTED_ORIGIN,
    cdn: { path: { caseSensitive: false } },
  });
  assert.equal(result.conflicts.length, 1);
  assert.ok(result.conflicts[0].key.includes('path=/admin'));
});

test('duplicate query params: different multiplicity, different keys', () => {
  const a = computeCacheKey(req({ query: 'tag=x&tag=y' }), {});
  const b = computeCacheKey(req({ query: 'tag=x' }), {});
  assert.notEqual(a.key, b.key);
  const c = computeCacheKey(req({ query: 'tag=y&tag=x' }), {});
  // Same names, different duplicate values -> different key.
  assert.notEqual(a.key, c.key);
});

test('ignored security parameter produces collision and finding', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice', query: 'page=1&token=alice-sig' }),
      req({ id: 'b', user: 'bob', query: 'page=1&token=bob-sig' }),
    ],
    origin: PROTECTED_ORIGIN,
    cdn: { query: { mode: 'blacklist', params: ['token'] } },
  });
  const codes = findingCodes(result);
  assert.ok(codes.includes('IGNORED_SECURITY_PARAM'));
  assert.ok(codes.includes('CROSS_USER_CACHE_HIT'));
  assert.ok(!result.conflicts[0].key.includes('alice-sig'));
});

test('multi-value cookies: same name twice differs from single value', () => {
  const a = computeCacheKey(req({ cookie: 'session=x; session=y' }), {
    cookies: ['session'],
  });
  const b = computeCacheKey(req({ cookie: 'session=x' }), {
    cookies: ['session'],
  });
  assert.notEqual(a.key, b.key);
  assert.ok(a.key.includes('cookie:session=x&y'));
});

test('host excluded from key collides different vhosts', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice', host: 'a.example.com' }),
      req({ id: 'b', user: 'bob', host: 'b.example.com' }),
    ],
    origin: PROTECTED_ORIGIN,
    cdn: { includeHost: false },
  });
  const codes = findingCodes(result);
  assert.ok(codes.includes('HOST_COLLISION'));
  assert.ok(codes.includes('CROSS_USER_CACHE_HIT'));
});

test('host case and default port do not split keys', () => {
  const a = computeCacheKey(req({ host: 'EXAMPLE.com' }), {});
  const b = computeCacheKey(req({ host: 'example.com:443' }), {});
  assert.equal(a.key, b.key);
});

test('same user with same key is not a conflict', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice' }),
      req({ id: 'b', user: 'alice' }),
    ],
    origin: PROTECTED_ORIGIN,
  });
  assert.equal(result.conflicts.length, 0);
  assert.ok(!findingCodes(result).includes('CROSS_USER_CACHE_HIT'));
});

test('conflict output carries canonical key components', () => {
  const result = auditIsolation({
    requests: [
      req({ id: 'a', user: 'alice', query: 'b=2&a=1' }),
      req({ id: 'b', user: 'bob', query: 'a=1&b=2' }),
    ],
    origin: PROTECTED_ORIGIN,
  });
  assert.equal(result.conflicts.length, 1);
  const { key, components } = result.conflicts[0];
  assert.ok(key.includes('query=a=1&b=2'));
  assert.equal(components.path, '/account');
  assert.deepEqual(components.query, [['a', '1'], ['b', '2']]);
});
