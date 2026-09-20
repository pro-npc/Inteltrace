import type { APIRoute } from 'astro';
import { json, fail, getEnv } from '../../../lib/http';
import { requireSession } from '../../../lib/auth';

export const prerender = false;

// Route guard for the client: returns the current user or 401. Refreshes the
// sliding 30-min session cookie on each call.
export const GET: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const r = await requireSession(context.request, env);
  if (!r) return fail('Unauthorized', 401);
  return json(
    {
      user: {
        badgeId: r.session.sub,
        name: r.session.name,
        role: r.session.role,
        email: r.session.email,
      },
    },
    200,
    { 'set-cookie': r.setCookie },
  );
};
