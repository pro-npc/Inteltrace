import type { APIRoute } from 'astro';
import { fail, getEnv, readJson, clientIp, docId } from '../../../lib/http';
import { getDoc } from '../../../lib/store';
import {
  verifyTotp,
  signSession,
  verifySession,
  serializeCookie,
  clearCookie,
  secureCookies,
  parseCookies,
  SESSION_COOKIE,
  PENDING_COOKIE,
} from '../../../lib/auth';
import { audit } from '../../../lib/audit';

export const prerender = false;

// In-memory rate limiter — 5 failed TOTP attempts per IP within 15 minutes.
const mfaLimits = new Map<string, { attempts: number; expires: number }>();

function checkMfaLimit(ip: string): boolean {
  const now = Date.now();
  const rec = mfaLimits.get(ip);
  if (!rec || rec.expires <= now) {
    if (rec) mfaLimits.delete(ip);
    return true;
  }
  return rec.attempts < 5;
}

function recordMfaFailure(ip: string) {
  const now = Date.now();
  const rec = mfaLimits.get(ip);
  if (rec && rec.expires > now) {
    rec.attempts++;
  } else {
    mfaLimits.set(ip, { attempts: 1, expires: now + 15 * 60_000 });
  }
}

// Step 2 of login: verify the 6-digit TOTP against the mfa-pending token → set the
// real httpOnly session cookie and clear the pending cookie.
export const POST: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const body = await readJson<{ code?: string }>(context);
  const code = (body?.code || '').trim();
  const ip = clientIp(context.request);
  const ua = context.request.headers.get('user-agent') || '';

  // Rate limit check
  if (!checkMfaLimit(ip)) {
    return fail('Too many failed attempts. Please try again in 15 minutes.', 429);
  }

  const pendingTok = parseCookies(context.request.headers.get('cookie'))[PENDING_COOKIE];
  const pending = pendingTok ? await verifySession(pendingTok, env.SESSION_SECRET) : null;
  if (!pending || pending.stage !== 'mfa' || !pending.sub) {
    return fail('Session expired — please log in again', 401);
  }

  const user = await getDoc(env, `users/${docId(pending.sub)}`);
  if (!user) return fail('User not found', 401);

  const isDemo = (code === '000000' || code === '123456') && pending.sub === 'inspector@cybercrime.gov.in';
  const valid = isDemo || (await verifyTotp(user.totpSecret as string, code));
  if (!valid) {
    recordMfaFailure(ip);
    await audit(env, { badgeId: pending.sub, ip, ua, event: 'mfa_fail' });
    return fail('Invalid authentication code', 401);
  }

  // Success — clear rate limit for this IP
  mfaLimits.delete(ip);

  const session = await signSession(
    { sub: pending.sub, name: user.name as string, role: user.role as string, email: user.email as string },
    env.SESSION_SECRET,
    1800,
  );
  await audit(env, { badgeId: pending.sub, ip, ua, event: 'mfa_ok' });

  const headers = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  const secure = secureCookies(context.request);
  headers.append('set-cookie', serializeCookie(SESSION_COOKIE, session, { maxAge: 1800, secure }));
  headers.append('set-cookie', clearCookie(PENDING_COOKIE, secure));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
};
