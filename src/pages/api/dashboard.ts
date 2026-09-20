import type { APIRoute } from 'astro';
import { json, fail, getEnv } from '../../lib/http';
import { requireSession } from '../../lib/auth';
import { getDashboard } from '../../lib/cases';

export const prerender = false;

// GET /api/dashboard — stats/global (baseline-backed) + recent cases + total count.
export const GET: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const guard = await requireSession(context.request, env);
  if (!guard) return fail('Unauthorized', 401);

  try {
    const payload = await getDashboard(env);
    return json(payload, 200, { 'set-cookie': guard.setCookie });
  } catch (err) {
    console.error('[API/dashboard] Failed to load dashboard:', err);
    return fail('Failed to retrieve dashboard telemetry', 500, { 'set-cookie': guard.setCookie });
  }
};
