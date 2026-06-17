import { assertSafeHost } from '../security/denylist.mjs';

// Client HTTP générique (style Postman) via le relais. Anti-SSRF STRICT (le VPS héberge d'autres services) :
// host résolu et vérifié AVANT la requête (denylist IP privées/link-local). Stateless, zéro log, réponses bornées.
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const MAX_BODY = 512 * 1024; // plafond de la réponse renvoyée au navigateur
const TIMEOUT = 20000;
// En-têtes que l'on n'autorise PAS le client à fixer (sécurité/cohérence).
const BLOCKED_REQ_HEADERS = new Set(['host', 'content-length', 'connection']);

export async function httpRequest({ method, url, headers, body }) {
  const m = String(method || 'GET').toUpperCase();
  if (!METHODS.has(m)) throw new Error('HTTP_BAD_METHOD');
  let target;
  try {
    target = new URL(String(url));
  } catch {
    throw new Error('HTTP_BAD_URL');
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error('HTTP_BAD_URL');
  await assertSafeHost(target.hostname); // anti-SSRF : refuse localhost / IP privées / link-local

  const reqHeaders = {};
  if (headers && typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      if (typeof k === 'string' && typeof v === 'string' && k.trim() && !BLOCKED_REQ_HEADERS.has(k.toLowerCase())) reqHeaders[k] = v;
    }
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
  const started = Date.now();
  try {
    const res = await fetch(target.toString(), {
      method: m,
      headers: reqHeaders,
      body: m === 'GET' || m === 'HEAD' ? undefined : (body ?? undefined),
      redirect: 'follow',
      signal: ctrl.signal,
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const truncated = buf.length > MAX_BODY;
    const text = buf.subarray(0, MAX_BODY).toString('utf8');
    const outHeaders = {};
    for (const [k, v] of res.headers.entries()) outHeaders[k] = v;
    return {
      status: res.status,
      statusText: res.statusText,
      headers: outHeaders,
      body: text,
      truncated,
      timeMs: Date.now() - started,
      size: buf.length,
    };
  } catch (err) {
    if (err?.name === 'AbortError') throw new Error('HTTP_TIMEOUT');
    throw new Error('HTTP_FETCH_ERROR');
  } finally {
    clearTimeout(timer);
  }
}
