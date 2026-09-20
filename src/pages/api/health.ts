import type { APIRoute } from 'astro';
import { json, getEnv } from '../../lib/http';
import { storeHealth } from '../../lib/store';
import { requireSession } from '../../lib/auth';

export const prerender = false;

// Liveness endpoint. Publicly returns operational status. Detailed diagnostics
// require an authenticated investigator session to prevent information disclosure.
export const GET: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const now = new Date().toISOString();

  const session = await requireSession(context.request, env);
  if (!session) {
    return json({ ok: true, service: 'inteltrace', status: 'operational', time: now });
  }

  const store = storeHealth(env);

  const config = {
    store: store.ok,
    encryptionAtRest: Boolean(env.ENCRYPTION_KEY),
    gemini: Boolean(env.GEMINI_API_KEY),
    etherscan: Boolean(env.ETHERSCAN_API_KEY),
    session: Boolean(env.SESSION_SECRET),
  };

  const apis: Record<string, string> = {
    // Local SQLite: reachable or not, no network involved.
    store: store.ok ? 'ok' : 'error',
  };

  try {
    const r = await fetch('https://api.coingecko.com/api/v3/ping');
    apis.coingecko = r.ok ? 'ok' : `status ${r.status}`;
  } catch {
    apis.coingecko = 'unreachable';
  }

  return json(
    {
      ok: true,
      service: 'inteltrace',
      status: 'operational',
      time: now,
      config,
      apis,
      storage: { path: store.path, cases: store.cases },
    },
    200,
    { 'set-cookie': session.setCookie },
  );
};
