import {
  normalizePath,
  normalizeHost,
  parseQuery,
  canonicalizeQuery,
  parseCookies,
} from './normalize.js';

// Query parameter names that commonly carry security-relevant state.
export const SECURITY_PARAM_NAMES = [
  'token',
  'access_token',
  'id_token',
  'auth',
  'sig',
  'signature',
  'session',
  'sessionid',
  'sid',
  'uid',
  'user',
  'userid',
  'api_key',
  'apikey',
  'key',
  'expires',
  'ticket',
  'code',
];

// Default CDN cache-key policy. Every field mirrors a knob real CDNs expose.
export const DEFAULT_CDN_POLICY = {
  includeHost: true,
  hostCaseSensitive: false,
  path: {
    dotSegments: true,
    collapseDoubleSlashes: true,
    caseSensitive: true,
    decodeUnreserved: true,
  },
  query: {
    // 'all' | 'none' | 'whitelist' | 'blacklist'
    mode: 'all',
    params: [],
    sort: true,
  },
  // Cookie names the CDN folds into the cache key.
  cookies: [],
  // Header names (lowercase) the CDN folds into the cache key.
  headers: [],
  // How the CDN treats the origin's Vary header:
  // 'origin' (honor it) | 'merge' (union with headers) | 'override' | 'ignore'
  varyHandling: 'origin',
  varyOverride: [],
};

export function mergePolicy(overrides = {}) {
  const base = DEFAULT_CDN_POLICY;
  return {
    ...base,
    ...overrides,
    path: { ...base.path, ...(overrides.path || {}) },
    query: { ...base.query, ...(overrides.query || {}) },
    cookies: overrides.cookies || base.cookies,
    headers: overrides.headers || base.headers,
    varyOverride: overrides.varyOverride || base.varyOverride,
  };
}

// Effective Vary header-name set after the CDN's handling is applied.
export function effectiveVary(originVary = [], policy = DEFAULT_CDN_POLICY) {
  const origin = originVary.map((h) => String(h).toLowerCase());
  switch (policy.varyHandling) {
    case 'ignore':
      return [];
    case 'override':
      return policy.varyOverride.map((h) => String(h).toLowerCase());
    case 'merge':
      return [...new Set([...origin, ...policy.headers.map((h) => h.toLowerCase())])];
    case 'origin':
    default:
      return origin;
  }
}

// Compute the canonical cache key for one request under a CDN policy.
// Returns { key, components } where components exposes each key part so
// findings can point at exactly which dimension was dropped.
export function computeCacheKey(request, policy = DEFAULT_CDN_POLICY, originVary = []) {
  const p = mergePolicy(policy);
  const components = {};

  if (p.includeHost) {
    components.host = normalizeHost(request.host, {
      caseSensitive: p.hostCaseSensitive,
    });
  }

  components.path = normalizePath(request.path, p.path);

  const pairs = parseQuery(request.query);
  let keyed;
  switch (p.query.mode) {
    case 'none':
      keyed = [];
      break;
    case 'whitelist': {
      const allow = new Set(p.query.params.map((n) => n.toLowerCase()));
      keyed = pairs.filter(([name]) => allow.has(name.toLowerCase()));
      break;
    }
    case 'blacklist': {
      const deny = new Set(p.query.params.map((n) => n.toLowerCase()));
      keyed = pairs.filter(([name]) => !deny.has(name.toLowerCase()));
      break;
    }
    case 'all':
    default:
      keyed = pairs;
  }
  components.query = canonicalizeQuery(keyed, { sort: p.query.sort });

  // Vary-derived headers/cookies, per the CDN's Vary handling.
  const vary = effectiveVary(originVary, p);
  const jar = parseCookies(request.cookie);
  const reqHeaders = {};
  for (const [name, value] of Object.entries(request.headers || {})) {
    reqHeaders[name.toLowerCase()] = value;
  }

  const varyParts = [];
  for (const name of vary) {
    if (name === 'cookie') {
      // Vary: Cookie pins the whole Cookie header.
      varyParts.push(['cookie', request.cookie || '']);
    } else {
      varyParts.push([name, reqHeaders[name] ?? '']);
    }
  }
  components.vary = varyParts;

  // Explicitly keyed cookies (CDN cookie whitelist).
  const cookieParts = [];
  for (const name of p.cookies) {
    const values = jar.get(name) || [];
    cookieParts.push([name, values.join('&')]);
  }
  components.cookies = cookieParts;

  // Explicitly keyed headers (e.g. authorization).
  const headerParts = [];
  for (const name of p.headers) {
    headerParts.push([name.toLowerCase(), reqHeaders[name.toLowerCase()] ?? '']);
  }
  components.headers = headerParts;

  const key = serializeKey(components);
  return { key, components };
}

function serializeKey(components) {
  const parts = [];
  if (components.host !== undefined) parts.push(`host=${components.host}`);
  parts.push(`path=${components.path}`);
  if (components.query.length > 0) {
    parts.push(
      `query=${components.query.map(([n, v]) => `${n}=${v}`).join('&')}`,
    );
  }
  for (const [name, value] of components.vary) {
    parts.push(`vary:${name}=${value}`);
  }
  for (const [name, value] of components.cookies) {
    parts.push(`cookie:${name}=${value}`);
  }
  for (const [name, value] of components.headers) {
    parts.push(`header:${name}=${value}`);
  }
  return parts.join('\n');
}
