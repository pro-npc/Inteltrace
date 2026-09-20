// Self-contained auth built on Web Crypto only (available in Node 18+ as a
// global): PBKDF2-SHA256 password hashing, RFC-6238 TOTP (HMAC-SHA1), HS256
// session JWTs, and cookie helpers. No Firebase Auth, no npm crypto dependency.

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------- encodings
function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return b64ToBytes(s);
}
function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------- passwords
const PBKDF2_ITER = 100_000;
export interface PasswordRecord {
  hash: string;
  salt: string;
  iterations: number;
}

export async function hashPassword(
  password: string,
  saltHex?: string,
  iterations = PBKDF2_ITER,
): Promise<PasswordRecord> {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    256,
  );
  return { hash: toHex(new Uint8Array(bits)), salt: toHex(salt), iterations };
}

export async function verifyPassword(password: string, rec: PasswordRecord): Promise<boolean> {
  if (!rec?.hash || !rec?.salt) return false;
  const check = await hashPassword(password, rec.salt, rec.iterations || PBKDF2_ITER);
  return timingSafeEqual(check.hash, rec.hash);
}

// ---------------------------------------------------------------- TOTP (RFC 6238)
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(s: string): Uint8Array<ArrayBuffer> {
  s = s.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function generateTotpSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

export function otpauthURI(secret: string, label: string, issuer = 'IntelTrace'): string {
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${label}`)}?${params.toString()}`;
}

async function hotp(keyBytes: Uint8Array<ArrayBuffer>, counter: number): Promise<string> {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array(buf)));
  const offset = hmac[hmac.length - 1] & 0xf;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (bin % 1_000_000).toString().padStart(6, '0');
}

export async function totpCode(secret: string, atMs = Date.now()): Promise<string> {
  return hotp(base32Decode(secret), Math.floor(atMs / 1000 / 30));
}

export async function verifyTotp(secret: string, token: string, window = 1, atMs = Date.now()): Promise<boolean> {
  token = (token || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(token)) return false;
  const counter = Math.floor(atMs / 1000 / 30);
  const key = base32Decode(secret);
  for (let w = -window; w <= window; w++) {
    if (timingSafeEqual(await hotp(key, counter + w), token)) return true;
  }
  return false;
}

// ---------------------------------------------------------------- session JWT (HS256)
async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

export interface SessionPayload {
  sub: string;
  name?: string;
  role?: string;
  email?: string;
  iat?: number;
  exp?: number;
  [k: string]: unknown;
}

export async function signSession(payload: SessionPayload, secret: string, ttlSec = 1800): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64url(enc.encode(JSON.stringify({ ...payload, iat: now, exp: now + ttlSec })));
  const unsigned = `${header}.${body}`;
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(unsigned)));
  return `${unsigned}.${b64url(sig)}`;
}

export async function verifySession(token: string, secret: string): Promise<SessionPayload | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64urlToBytes(s), enc.encode(`${h}.${b}`));
  if (!ok) return null;
  let payload: SessionPayload;
  try {
    payload = JSON.parse(dec.decode(b64urlToBytes(b)));
  } catch {
    return null;
  }
  if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

// ---------------------------------------------------------------- cookies
export const SESSION_COOKIE = 'it_session';
export const PENDING_COOKIE = 'it_mfa_pending';

export function serializeCookie(
  name: string,
  value: string,
  opts: {
    maxAge?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'Lax' | 'Strict' | 'None';
    path?: string;
  } = {},
): string {
  const p: string[] = [`${name}=${value}`, `Path=${opts.path ?? '/'}`];
  if (opts.maxAge !== undefined) p.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly !== false) p.push('HttpOnly');
  if (opts.secure !== false) p.push('Secure');
  p.push(`SameSite=${opts.sameSite ?? 'Lax'}`);
  return p.join('; ');
}

export function clearCookie(name: string, secure = true): string {
  return `${name}=; Path=/; Max-Age=0; HttpOnly;${secure ? ' Secure;' : ''} SameSite=Lax`;
}

/**
 * Whether the `Secure` attribute can be set on cookies for this request.
 *
 * Secure cookies are only stored over HTTPS, with loopback exempted as a
 * trustworthy origin. The server now runs as plain HTTP on the investigator's
 * machine, so over localhost `Secure` still works — but `--host` also serves the
 * LAN address, and there a Secure cookie is silently discarded by the browser,
 * which reads as "login succeeds then bounces back to the login page".
 *
 * Defaults to true on anything unparseable: better to break a cookie than to
 * send a session token in the clear.
 */
export function secureCookies(request: Request): boolean {
  try {
    const url = new URL(request.url);
    if (url.protocol === 'https:') return true;
    const host = url.hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  } catch {
    return true;
  }
}

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    if (k) out[k] = part.slice(idx + 1).trim();
  }
  return out;
}

// ---------------------------------------------------------------- guards
export async function getSession(request: Request, secret: string): Promise<SessionPayload | null> {
  const tok = parseCookies(request.headers.get('cookie'))[SESSION_COOKIE];
  return tok ? verifySession(tok, secret) : null;
}

/**
 * Require a valid session. Returns the session plus a refreshed cookie (sliding
 * 30-min idle timeout), or null when unauthenticated.
 */
export async function requireSession(
  request: Request,
  env: Env,
): Promise<{ session: SessionPayload; setCookie: string } | null> {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return null;
  const fresh = await signSession(
    { sub: session.sub, name: session.name, role: session.role, email: session.email },
    env.SESSION_SECRET,
    1800,
  );
  return {
    session,
    setCookie: serializeCookie(SESSION_COOKIE, fresh, {
      maxAge: 1800,
      secure: secureCookies(request),
    }),
  };
}
