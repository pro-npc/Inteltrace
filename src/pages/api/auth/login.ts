import type { APIRoute } from 'astro';
import { json, fail, getEnv, readJson, clientIp, docId } from '../../../lib/http';
import { getDoc } from '../../../lib/store';
import { verifyPassword, signSession, serializeCookie, secureCookies, PENDING_COOKIE } from '../../../lib/auth';
import { audit } from '../../../lib/audit';

export const prerender = false;

// Simple in-memory rate limiting for the isolate (4 attempts / 15 mins)
const rateLimits = new Map<string, { attempts: number; expires: number }>();

function checkLimit(key: string): boolean {
  const now = Date.now();
  const rec = rateLimits.get(key);
  if (!rec || rec.expires <= now) {
    if (rec) rateLimits.delete(key);
    return true;
  }
  return rec.attempts < 4;
}

function recordFailure(key: string) {
  const now = Date.now();
  const rec = rateLimits.get(key);
  if (rec && rec.expires > now) {
    rec.attempts++;
  } else {
    rateLimits.set(key, { attempts: 1, expires: now + 15 * 60000 });
  }
}

// Step 1 of login: verify badge id + password → issue a short-lived "mfa-pending"
// token. Does NOT grant a session; the TOTP step does.
export const POST: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const body = await readJson<{ badgeId?: string; password?: string }>(context);
  const badgeId = (body?.badgeId || '').trim();
  const password = body?.password || '';
  const ip = clientIp(context.request);
  const ua = context.request.headers.get('user-agent') || '';

  const rateKey = `${ip}:${badgeId}`;
  if (!checkLimit(rateKey)) {
    return fail('Too many failed attempts. Please try again in 15 minutes.', 429);
  }

  if (!badgeId || !password) return fail('Badge ID and password are required', 400);

  const user = await getDoc(env, `users/${docId(badgeId)}`);
  const ok =
    user &&
    (await verifyPassword(password, {
      hash: user.passwordHash as string,
      salt: user.passwordSalt as string,
      iterations: user.passwordIter as number,
    }));

  if (!user || !ok) {
    recordFailure(rateKey);
    await audit(env, { badgeId, ip, ua, event: 'login_fail' });
    return fail('Invalid credentials', 401);
  }

  rateLimits.delete(rateKey);
  const pending = await signSession({ sub: badgeId, stage: 'mfa' }, env.SESSION_SECRET, 300);
  await audit(env, { badgeId, ip, ua, event: 'login_password_ok' });
  return json({ ok: true, mfaRequired: true }, 200, {
    'set-cookie': serializeCookie(PENDING_COOKIE, pending, {
      maxAge: 300,
      secure: secureCookies(context.request),
    }),
  });
};
