import {
  computeCacheKey,
  effectiveVary,
  mergePolicy,
  SECURITY_PARAM_NAMES,
} from './cacheKey.js';
import { parseQuery, parseCookies, normalizePath } from './normalize.js';

export const SEVERITY = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  info: 'info',
};

// Parse Cache-Control into a directive map (lowercase names).
export function parseCacheControl(header) {
  const directives = new Map();
  if (!header) return directives;
  for (const part of String(header).split(',')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) directives.set(trimmed.toLowerCase(), true);
    else {
      directives.set(
        trimmed.slice(0, eq).trim().toLowerCase(),
        trimmed.slice(eq + 1).trim().replace(/^"|"$/g, ''),
      );
    }
  }
  return directives;
}

// Would a shared (CDN) cache store this response?
export function isSharedCacheable(cacheControlHeader) {
  const d = parseCacheControl(cacheControlHeader);
  if (d.has('no-store') || d.has('private')) return false;
  if (d.has('public')) return true;
  const maxAge = Number(d.get('s-maxage') ?? d.get('max-age'));
  return Number.isFinite(maxAge) && maxAge > 0;
}

function requestAuthContext(request) {
  const headers = {};
  for (const [name, value] of Object.entries(request.headers || {})) {
    headers[name.toLowerCase()] = value;
  }
  return {
    authorization: headers.authorization || null,
    cookies: parseCookies(request.cookie),
  };
}

// Audit a set of requests (from different users) against an origin response
// policy and a CDN cache-key policy.
//
// origin: { protected, cacheControl, vary: [] }
// Returns { findings, conflicts, keys }.
export function auditIsolation({ requests, origin = {}, cdn = {} } = {}) {
  const policy = mergePolicy(cdn);
  const vary = origin.vary || [];
  const effVary = effectiveVary(vary, policy);
  const findings = [];
  const keys = new Map();

  for (const request of requests) {
    keys.set(request.id, computeCacheKey(request, policy, vary));
  }

  // 1. Protected resource stored by a shared cache.
  const cacheable = isSharedCacheable(origin.cacheControl);
  if (origin.protected && cacheable) {
    findings.push({
      code: 'PROTECTED_RESOURCE_CACHEABLE',
      severity: SEVERITY.high,
      message:
        'Origin marks this resource as access-controlled, yet its ' +
        'Cache-Control allows a shared cache to store it. Isolation depends ' +
        'entirely on the cache key.',
    });
  }

  // 2. Authentication context absent from the cache key.
  const keyedHeaders = new Set(policy.headers.map((h) => h.toLowerCase()));
  const keyedCookies = new Set(policy.cookies.map((c) => c.toLowerCase()));
  const varySet = new Set(effVary);
  const authKeyed =
    keyedHeaders.has('authorization') || varySet.has('authorization');
  const cookieKeyed = keyedCookies.size > 0 || varySet.has('cookie');

  const authedRequests = requests.filter((r) => {
    const ctx = requestAuthContext(r);
    return ctx.authorization || ctx.cookies.size > 0;
  });
  if (origin.protected && cacheable && authedRequests.length > 0) {
    const anyAuthHeader = authedRequests.some(
      (r) => requestAuthContext(r).authorization,
    );
    if (anyAuthHeader && !authKeyed) {
      findings.push({
        code: 'AUTH_CONTEXT_MISSING',
        severity: SEVERITY.critical,
        message:
          'Requests carry Authorization but neither the CDN key rules nor ' +
          'the effective Vary include it. Authenticated responses can be ' +
          'served to other users.',
      });
    }
    const sensitive = new Set();
    for (const r of authedRequests) {
      for (const name of requestAuthContext(r).cookies.keys()) {
        sensitive.add(name);
      }
    }
    const missing = [...sensitive].filter(
      (name) => !keyedCookies.has(name.toLowerCase()) && !varySet.has('cookie'),
    );
    if (missing.length > 0 && !cookieKeyed) {
      findings.push({
        code: 'SENSITIVE_COOKIE_MISSING',
        severity: SEVERITY.critical,
        message:
          `Sensitive cookies not folded into the cache key: ` +
          missing.join(', ') +
          '. Session-scoped responses are keyed as anonymous.',
        details: { cookies: missing },
      });
    }
  }

  // 3. Vary merge errors: origin Vary entries dropped by CDN handling.
  if (policy.varyHandling === 'ignore' && vary.length > 0) {
    findings.push({
      code: 'VARY_MERGE_ERROR',
      severity: SEVERITY.high,
      message:
        `CDN ignores the origin Vary header (${vary.join(', ')}). ` +
        'Origin-assumed key dimensions are silently dropped.',
      details: { originVary: vary, effectiveVary: effVary },
    });
  } else if (policy.varyHandling === 'override') {
    const dropped = vary
      .map((h) => h.toLowerCase())
      .filter((h) => !effVary.includes(h));
    if (dropped.length > 0) {
      findings.push({
        code: 'VARY_MERGE_ERROR',
        severity: SEVERITY.high,
        message:
          `CDN Vary override drops origin Vary entries: ${dropped.join(', ')}.`,
        details: { originVary: vary, effectiveVary: effVary },
      });
    }
  }

  // 4. Ignored security-relevant query parameters.
  const securityNames = new Set(SECURITY_PARAM_NAMES);
  const ignoredSecurity = new Set();
  for (const request of requests) {
    for (const [name] of parseQuery(request.query)) {
      const lower = name.toLowerCase();
      if (!securityNames.has(lower)) continue;
      const keyed =
        policy.query.mode === 'all' ||
        (policy.query.mode === 'whitelist' &&
          policy.query.params.some((p) => p.toLowerCase() === lower)) ||
        (policy.query.mode === 'blacklist' &&
          !policy.query.params.some((p) => p.toLowerCase() === lower));
      if (!keyed) ignoredSecurity.add(name);
    }
  }
  if (ignoredSecurity.size > 0) {
    findings.push({
      code: 'IGNORED_SECURITY_PARAM',
      severity: SEVERITY.high,
      message:
        'Security-relevant query parameters excluded from the cache key: ' +
        [...ignoredSecurity].join(', ') +
        '. Signed/tokenized URLs collapse onto one cache object.',
      details: { params: [...ignoredSecurity] },
    });
  }

  // 5. Host differences collapsed.
  const hosts = new Set(requests.map((r) => r.host).filter(Boolean));
  if (!policy.includeHost && hosts.size > 1) {
    findings.push({
      code: 'HOST_COLLISION',
      severity: SEVERITY.medium,
      message:
        'Host is not part of the cache key but requests span multiple ' +
        'hosts. Cross-vhost cache sharing is possible.',
      details: { hosts: [...hosts] },
    });
  }

  // 6. Path encoding / normalization inconsistencies between requests.
  const byNormalized = new Map();
  for (const request of requests) {
    const normalized = normalizePath(request.path, policy.path);
    if (!byNormalized.has(normalized)) byNormalized.set(normalized, []);
    byNormalized.get(normalized).push(request);
  }
  for (const [normalized, group] of byNormalized) {
    const raws = new Set(group.map((r) => r.path));
    if (raws.size > 1) {
      findings.push({
        code: 'PATH_ENCODING_INCONSISTENCY',
        severity: SEVERITY.medium,
        message:
          `Distinct raw paths ${[...raws].join(', ')} normalize to ` +
          `"${normalized}". If the origin and CDN normalize differently, ` +
          'one user\'s object can be stored under another\'s key.',
        details: { normalized, rawPaths: [...raws] },
      });
    }
  }

  // 7. Cross-user conflicts: identical canonical keys, different users.
  const conflicts = [];
  for (let i = 0; i < requests.length; i += 1) {
    for (let j = i + 1; j < requests.length; j += 1) {
      const a = requests[i];
      const b = requests[j];
      if (a.user === b.user) continue;
      const keyA = keys.get(a.id);
      const keyB = keys.get(b.id);
      if (keyA.key === keyB.key) {
        conflicts.push({
          a: a.id,
          b: b.id,
          users: [a.user, b.user],
          key: keyA.key,
          components: keyA.components,
        });
      }
    }
  }
  if (conflicts.length > 0) {
    findings.push({
      code: 'CROSS_USER_CACHE_HIT',
      severity: SEVERITY.critical,
      message:
        `${conflicts.length} request pair(s) from different users produce ` +
        'the same canonical cache key.',
      details: {
        pairs: conflicts.map((c) => ({ a: c.a, b: c.b, key: c.key })),
      },
    });
  }

  return { findings, conflicts, keys };
}
