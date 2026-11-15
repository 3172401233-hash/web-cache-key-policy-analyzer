// Request-component normalization used to build canonical cache keys.

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

// Decode percent-encoded octets that represent unreserved characters only.
// Encodings of reserved characters (e.g. %2F) are preserved (uppercased) so
// that "/a%2Fb" never collapses into "/a/b".
export function decodeUnreserved(input) {
  return input.replace(/%([0-9A-Fa-f]{2})/g, (match, hex) => {
    const ch = String.fromCharCode(parseInt(hex, 16));
    return UNRESERVED.test(ch) ? ch : `%${hex.toUpperCase()}`;
  });
}

// RFC 3986 section 5.2.4 remove_dot_segments.
export function removeDotSegments(path) {
  const input = path.split('');
  const output = [];
  while (input.length > 0) {
    const joined = input.join('');
    if (joined.startsWith('../')) {
      input.splice(0, 3);
    } else if (joined.startsWith('./')) {
      input.splice(0, 2);
    } else if (joined.startsWith('/./')) {
      input.splice(0, 3);
      input.unshift('/');
    } else if (joined === '/.') {
      input.splice(0, 2);
      input.unshift('/');
    } else if (joined.startsWith('/../')) {
      input.splice(0, 4);
      input.unshift('/');
      popSegment(output);
    } else if (joined === '/..') {
      input.splice(0, 3);
      input.unshift('/');
      popSegment(output);
    } else if (joined === '.' || joined === '..') {
      input.splice(0, input.length);
    } else {
      moveSegment(input, output);
    }
  }
  return output.join('');
}

function popSegment(output) {
  const joined = output.join('');
  const idx = joined.lastIndexOf('/');
  output.length = 0;
  output.push(idx <= 0 ? '' : joined.slice(0, idx));
}

function moveSegment(input, output) {
  const joined = input.join('');
  let end;
  if (joined.startsWith('/')) {
    const next = joined.indexOf('/', 1);
    end = next === -1 ? joined.length : next;
  } else {
    const next = joined.indexOf('/');
    end = next === -1 ? joined.length : next;
  }
  output.push(joined.slice(0, end));
  input.splice(0, end);
}

export function collapseSlashes(path) {
  return path.replace(/\/{2,}/g, '/');
}

// Normalize a request path according to CDN normalization settings.
export function normalizePath(rawPath, options = {}) {
  const {
    dotSegments = true,
    collapseDoubleSlashes = true,
    caseSensitive = true,
    decodeUnreserved: decode = true,
  } = options;
  let path = rawPath || '/';
  if (decode) path = decodeUnreserved(path);
  if (dotSegments) path = removeDotSegments(path);
  if (collapseDoubleSlashes) path = collapseSlashes(path);
  if (!caseSensitive) path = path.toLowerCase();
  if (path === '') path = '/';
  return path;
}

export function normalizeHost(host, { caseSensitive = false } = {}) {
  if (!host) return '';
  let value = String(host).trim();
  if (!caseSensitive) value = value.toLowerCase();
  // Strip default ports so "example.com:443" and "example.com" agree.
  value = value.replace(/:(443|80)$/, '');
  return value;
}

// Parse a query string into an ordered list of [name, value] pairs.
// Duplicate names are preserved as separate pairs (order retained).
export function parseQuery(queryString) {
  if (!queryString) return [];
  const raw = queryString.startsWith('?') ? queryString.slice(1) : queryString;
  if (raw === '') return [];
  return raw.split('&').map((pair) => {
    const eq = pair.indexOf('=');
    const name = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? '' : pair.slice(eq + 1);
    return [decodeUnreserved(name), decodeUnreserved(value)];
  });
}

// Canonicalize query pairs for a cache key: optionally drop ignored params,
// optionally sort. Duplicates of the same name keep their relative order.
export function canonicalizeQuery(pairs, { ignore = [], sort = true } = {}) {
  const ignored = new Set(ignore.map((n) => n.toLowerCase()));
  const kept = pairs.filter(([name]) => !ignored.has(name.toLowerCase()));
  if (!sort) return kept;
  return [...kept].sort((a, b) =>
    a[0] === b[0] ? 0 : a[0] < b[0] ? -1 : 1,
  );
}

// Parse a Cookie header into a name -> [values] map. A cookie name appearing
// more than once keeps all of its values in order.
export function parseCookies(cookieHeader) {
  const jar = new Map();
  if (!cookieHeader) return jar;
  for (const part of String(cookieHeader).split(';')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const eq = trimmed.indexOf('=');
    const name = (eq === -1 ? trimmed : trimmed.slice(0, eq)).trim();
    const value = eq === -1 ? '' : trimmed.slice(eq + 1).trim();
    if (!jar.has(name)) jar.set(name, []);
    jar.get(name).push(value);
  }
  return jar;
}
