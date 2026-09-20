import type { APIRoute } from 'astro';
import { fail, getEnv, readJson } from '../../lib/http';
import { requireSession } from '../../lib/auth';
import { getCaseDoc } from '../../lib/cases';
import { runCopilotStream, type CopilotTurn } from '../../lib/gemini';
import { CANONICAL_CASE_ID } from '../../lib/fixtures/canonicalCase';

export const prerender = false;

// ── CSRF origin validation ───────────────────────────────────────────────────
// Loopback plus the request's own origin (so `--host` on a LAN address still
// works). No external origin is accepted.
function validateOrigin(request: Request, _env: Env): boolean {
  const origin = request.headers.get('origin') || '';
  const referer = request.headers.get('referer') || '';
  if (!origin && !referer) return true;

  let reqOrigin = '';
  try { reqOrigin = new URL(request.url).origin; } catch {}

  const allowed = [
    'http://localhost',
    'https://localhost',
    'http://127.0.0.1',
    'https://127.0.0.1',
  ];
  if (reqOrigin) allowed.push(reqOrigin);

  return allowed.some(a => origin.startsWith(a) || referer.startsWith(a));
}

// POST /api/copilot — { query, caseId?, history? } → Gemini answer grounded on the
// stored case view-model → { text, action } (the exact contract AICopilot renders).
export const POST: APIRoute = async (context) => {
  const env = getEnv(context.locals);

  // CSRF check
  if (!validateOrigin(context.request, env)) {
    return fail('Forbidden — cross-origin requests are not allowed', 403);
  }

  const guard = await requireSession(context.request, env);
  if (!guard) return fail('Unauthorized', 401);

  const setCookie = { 'set-cookie': guard.setCookie };
  const body = await readJson<{ query?: string; caseId?: string; history?: CopilotTurn[] }>(context);
  const query = (body?.query || '').trim();
  const caseId = (body?.caseId || '').trim() || CANONICAL_CASE_ID;
  const history = Array.isArray(body?.history) ? body!.history! : [];

  if (!query) return fail('query is required', 400, setCookie);

  // Ground the copilot on the real case doc; a null doc is fine — gemini.ts falls
  // back to the curated golden dossier for the canonical case.
  let doc = null;
  try {
    doc = await getCaseDoc(env, caseId);
  } catch {
    doc = null;
  }

  // runCopilot never throws (it degrades to a clean fallback), but guard anyway so
  // the UI always receives a renderable { text, action } payload — never a 5xx.
  try {
    return await runCopilotStream(env, doc, caseId, query, history);
  } catch {
    const body = `data: ${JSON.stringify({ text: 'The forensic copilot is temporarily unavailable. Please explore the case tabs directly.', action: null })}\n\n`;
    return new Response(body, { headers: { 'content-type': 'text/event-stream' } });
  }
};
