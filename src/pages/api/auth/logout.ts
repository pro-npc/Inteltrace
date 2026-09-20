import type { APIRoute } from 'astro';
import { clearCookie, secureCookies, SESSION_COOKIE, PENDING_COOKIE } from '../../../lib/auth';

export const prerender = false;

// The expiry cookie has to carry the same `Secure` decision as the cookie that
// set it: over a plain-HTTP LAN address the browser discards a Secure cookie
// outright, so a hardcoded one would leave the session cookie in place and the
// logout would silently do nothing.
function expire(request: Request): Headers {
  const secure = secureCookies(request);
  const headers = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  headers.append('set-cookie', clearCookie(SESSION_COOKIE, secure));
  headers.append('set-cookie', clearCookie(PENDING_COOKIE, secure));
  return headers;
}

export const POST: APIRoute = ({ request }) =>
  new Response(JSON.stringify({ ok: true }), { status: 200, headers: expire(request) });

// Allow GET for convenience (e.g. a plain link), same effect.
export const GET: APIRoute = ({ request }) =>
  new Response(JSON.stringify({ ok: true }), { status: 200, headers: expire(request) });
