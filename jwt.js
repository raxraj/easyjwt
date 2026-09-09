export const SUPPORTED_ALGS = {
  HS256: { family: 'HMAC', hash: 'SHA-256' }, HS384: { family: 'HMAC', hash: 'SHA-384' }, HS512: { family: 'HMAC', hash: 'SHA-512' },
  RS256: { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, RS384: { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, RS512: { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  PS256: { family: 'RSA-PSS', hash: 'SHA-256' }, PS384: { family: 'RSA-PSS', hash: 'SHA-384' }, PS512: { family: 'RSA-PSS', hash: 'SHA-512' },
  ES256: { family: 'ECDSA', hash: 'SHA-256', curve: 'P-256' }, ES384: { family: 'ECDSA', hash: 'SHA-384', curve: 'P-384' }, ES512: { family: 'ECDSA', hash: 'SHA-512', curve: 'P-521' },
};

const utf8 = new TextEncoder();
const decoder = new TextDecoder();

export function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Segment is not valid Base64URL.');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  try { return Uint8Array.from(atob(padded), char => char.charCodeAt(0)); }
  catch { throw new Error('Segment is not valid Base64URL.'); }
}
export function encodeBase64Url(value) {
  const bytes = typeof value === 'string' ? utf8.encode(value) : value;
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
export function parseJwt(token) {
  const parts = token.trim().split('.');
  if (parts.length === 5) return { type: 'JWE', parts };
  if (parts.length !== 3) throw new Error('A compact signed JWT must have exactly three dot-separated parts.');
  let header, payload;
  try { header = JSON.parse(decoder.decode(decodeBase64Url(parts[0]))); }
  catch { throw new Error('Header is not valid JSON.'); }
  try { payload = JSON.parse(decoder.decode(decodeBase64Url(parts[1]))); }
  catch { throw new Error('Payload is not valid JSON.'); }
  if (!header || Array.isArray(header) || !payload || Array.isArray(payload)) throw new Error('JWT header and payload must be JSON objects.');
  return { type: 'JWS', parts, header, payload, signature: parts[2] };
}
export function pretty(value) { return JSON.stringify(value, null, 2); }
export function encodeJson(value) { return encodeBase64Url(JSON.stringify(value)); }
export function humanTime(seconds, now = Date.now()) {
  if (!Number.isFinite(Number(seconds))) return null;
  const date = new Date(Number(seconds) * 1000);
  const delta = date.getTime() - now;
  const abs = Math.abs(delta);
  const units = abs < 60000 ? ['second', 1000] : abs < 3600000 ? ['minute', 60000] : abs < 86400000 ? ['hour', 3600000] : ['day', 86400000];
  const n = Math.max(1, Math.floor(abs / units[1]));
  const relative = delta >= 0 ? `Expires in ${n} ${units[0]}${n === 1 ? '' : 's'}` : `Expired ${n} ${units[0]}${n === 1 ? '' : 's'} ago`;
  return { local: date.toLocaleString(), utc: date.toUTCString(), iso: date.toISOString(), relative, date };
}
export function lint(header, payload, now = Date.now()) {
  const findings = [];
  const add = (severity, title, detail) => findings.push({ severity, title, detail });
  const alg = header.alg;
  if (!alg) add('error', 'Missing signing algorithm', 'The header has no alg claim.');
  else if (alg === 'none') add('error', 'Unsigned token', 'alg: none accepts no signature and must not be trusted for authentication.');
  else if (!SUPPORTED_ALGS[alg]) add('warning', 'Unsupported or risky algorithm', `${alg} is not supported by this local verifier.`);
  if (header.typ && header.typ !== 'JWT') add('info', 'Non-standard token type', `typ is ${header.typ}; confirm this is expected.`);
  for (const claim of ['exp', 'iat', 'nbf']) {
    if (!(claim in payload)) add(claim === 'exp' ? 'warning' : 'info', `Missing ${claim}`, claim === 'exp' ? 'Tokens should normally have a bounded expiry.' : `Consider adding ${claim} for clearer token lifecycle controls.`);
    else if (!Number.isFinite(Number(payload[claim]))) add('error', `Invalid ${claim}`, `${claim} must be a NumericDate in Unix seconds.`);
  }
  const exp = Number(payload.exp), iat = Number(payload.iat), nbf = Number(payload.nbf), nowSeconds = now / 1000;
  if (Number.isFinite(exp) && exp < nowSeconds) add('warning', 'Token expired', 'The exp timestamp is in the past on this device.');
  if (Number.isFinite(nbf) && nbf > nowSeconds) add('warning', 'Token not active yet', 'The nbf timestamp is in the future on this device; check clock skew.');
  if (Number.isFinite(iat) && iat > nowSeconds + 300) add('warning', 'Issued in the future', 'iat is more than five minutes ahead of this device clock.');
  if (Number.isFinite(exp) && Number.isFinite(iat) && exp <= iat) add('error', 'Invalid token lifetime', 'exp must be later than iat.');
  const pii = /(pass(word|wd)?|secret|api[-_]?key|credential|private[-_]?key|access[-_]?token|refresh[-_]?token|hash|ssn|social[-_]?security|internal|server[-_]?path|home\/|\/var\/|\/etc\/)/i;
  const scan = (value, path = '') => {
    if (value && typeof value === 'object') Object.entries(value).forEach(([key, child]) => scan(child, path ? `${path}.${key}` : key));
    else if (pii.test(path) || (typeof value === 'string' && (pii.test(value) || /-----BEGIN [A-Z ]+ KEY-----/.test(value)))) add('warning', 'Possible sensitive data in payload', `Review ${path || 'payload'}: JWT payloads are readable by anyone holding the token.`);
  };
  scan(payload);
  add('info', 'Payloads are not encrypted', 'Base64URL encoding is reversible; do not place confidential data in a JWS payload.');
  return findings;
}
function pemBytes(pem) {
  const body = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, '');
  if (!body) throw new Error('Paste a PEM-formatted key.');
  try { return Uint8Array.from(atob(body), c => c.charCodeAt(0)); } catch { throw new Error('PEM body is not valid Base64.'); }
}
function cryptoAlgorithm(spec) {
  if (spec.family === 'HMAC') return { name: 'HMAC', hash: spec.hash };
  if (spec.family === 'ECDSA') return { name: 'ECDSA', namedCurve: spec.curve };
  return { name: spec.family, hash: spec.hash };
}
export async function importKey(alg, rawKey, usage) {
  const spec = SUPPORTED_ALGS[alg];
  if (!spec) throw new Error(`Algorithm ${alg || '(missing)'} is not supported.`);
  if (spec.family === 'HMAC') return crypto.subtle.importKey('raw', utf8.encode(rawKey), cryptoAlgorithm(spec), false, [usage]);
  const format = usage === 'verify' ? 'spki' : 'pkcs8';
  return crypto.subtle.importKey(format, pemBytes(rawKey), cryptoAlgorithm(spec), false, [usage]);
}
export async function verifyJwt(parsed, keyText) {
  const spec = SUPPORTED_ALGS[parsed.header.alg];
  if (!spec) throw new Error(`Algorithm ${parsed.header.alg || '(missing)'} is not supported.`);
  const key = await importKey(parsed.header.alg, keyText, 'verify');
  const signed = utf8.encode(`${parsed.parts[0]}.${parsed.parts[1]}`);
  const signature = decodeBase64Url(parsed.signature);
  const params = spec.family === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: Number(spec.hash.slice(4)) } : spec.family === 'ECDSA' ? { name: 'ECDSA', hash: spec.hash } : spec.family === 'HMAC' ? { name: 'HMAC' } : { name: spec.family };
  return crypto.subtle.verify(params, key, signature, signed);
}
export async function signJwt(header, payload, keyText) {
  const spec = SUPPORTED_ALGS[header.alg];
  if (!spec) throw new Error(`Algorithm ${header.alg || '(missing)'} is not supported.`);
  const key = await importKey(header.alg, keyText, 'sign');
  const signingInput = `${encodeJson(header)}.${encodeJson(payload)}`;
  const params = spec.family === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: Number(spec.hash.slice(4)) } : spec.family === 'ECDSA' ? { name: 'ECDSA', hash: spec.hash } : { name: spec.family };
  const signature = await crypto.subtle.sign(params, key, utf8.encode(signingInput));
  return `${signingInput}.${encodeBase64Url(new Uint8Array(signature))}`;
}
