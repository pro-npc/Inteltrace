import type { APIRoute } from 'astro';
import { json, fail, getEnv } from '../../lib/http';
import { requireSession } from '../../lib/auth';
import { listCases } from '../../lib/cases';

export const prerender = false;

// GET /api/cases — every case, most recently analysed first (history + dashboard).
export const GET: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const guard = await requireSession(context.request, env);
  if (!guard) return fail('Unauthorized', 401);

  try {
    const cases = await listCases(env, 200);
    return json({ cases }, 200, { 'set-cookie': guard.setCookie });
  } catch (err) {
    console.error('[API/cases] Failed to list cases:', err);
    return fail('Failed to retrieve case registry', 500, { 'set-cookie': guard.setCookie });
  }
};
