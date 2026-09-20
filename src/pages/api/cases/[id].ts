import type { APIRoute } from 'astro';
import { json, fail, getEnv, clientIp } from '../../../lib/http';
import { requireSession } from '../../../lib/auth';
import { getCaseDoc, removeCase, isValidCaseId } from '../../../lib/cases';
import { audit } from '../../../lib/audit';

export const prerender = false;

// GET /api/cases/:id — the full denormalised case view-model (Results page).
export const GET: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const guard = await requireSession(context.request, env);
  if (!guard) return fail('Unauthorized', 401);

  const id = String(context.params.id || '').trim();
  if (!id || !isValidCaseId(id)) {
    return fail('Invalid case identifier', 400, { 'set-cookie': guard.setCookie });
  }

  try {
    const doc = await getCaseDoc(env, id);
    if (!doc || !doc.caseId) return fail('Case not found', 404, { 'set-cookie': guard.setCookie });
    return json(doc, 200, { 'set-cookie': guard.setCookie });
  } catch (err) {
    console.error(`[API/cases/id] Failed to load case:`, err);
    return fail('Failed to retrieve case details', 500, { 'set-cookie': guard.setCookie });
  }
};

// PATCH /api/cases/:id — update case status.
export const PATCH: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const guard = await requireSession(context.request, env);
  if (!guard) return fail('Unauthorized', 401);

  const id = String(context.params.id || '').trim();
  if (!id || !isValidCaseId(id)) {
    return fail('Invalid case identifier', 400, { 'set-cookie': guard.setCookie });
  }

  try {
    const body = await context.request.json();
    const status = body.status === 'CLOSED' ? 'CLOSED' : 'ACTIVE';
    const { closeCase } = await import('../../../lib/cases');
    await closeCase(env, id, status);
    await audit(env, {
      badgeId: guard.session.sub,
      ip: clientIp(context.request),
      ua: context.request.headers.get('user-agent') || '',
      event: `status:${id}:${status}`,
    });
    return json({ ok: true, id, status }, 200, { 'set-cookie': guard.setCookie });
  } catch (err) {
    console.error(`[API/cases/id] Failed to patch case:`, err);
    return fail('Failed to update case record', 500, { 'set-cookie': guard.setCookie });
  }
};

// DELETE /api/cases/:id — close/remove a case.
export const DELETE: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const guard = await requireSession(context.request, env);
  if (!guard) return fail('Unauthorized', 401);

  const id = String(context.params.id || '').trim();
  if (!id || !isValidCaseId(id)) {
    return fail('Invalid case identifier', 400, { 'set-cookie': guard.setCookie });
  }

  try {
    await removeCase(env, id);
    await audit(env, {
      badgeId: guard.session.sub,
      ip: clientIp(context.request),
      ua: context.request.headers.get('user-agent') || '',
      event: `delete:${id}`,
    });
    return json({ ok: true, id }, 200, { 'set-cookie': guard.setCookie });
  } catch (err) {
    console.error(`[API/cases/id] Failed to delete case:`, err);
    return fail('Failed to delete case record', 500, { 'set-cookie': guard.setCookie });
  }
};
