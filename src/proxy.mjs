import { Readable } from 'node:stream';
import { resolveTarget, PROVIDERS } from './allowlist.mjs';
import { safeLogLine } from './log.mjs';

// En-têtes à NE PAS réémettre vers l'amont (hop-by-hop + relais-only).
const DROP = new Set(['host', 'connection', 'content-length', 'x-pp-token', 'x-pp-base-url', 'origin', 'referer', 'accept-encoding']);

// Proxy TRANSPARENT (audit 05 D3/§4.2) : réémet vers la base-URL résolue, pipe le SSE NON bufferisé.
export function registerAiProxy(app, opts = {}) {
  app.post('/ai/:provider/*', async (req, reply) => {
    if (opts.verifyAccess && !(await opts.verifyAccess(req))) {
      reply.code(401).send({ error: 'unauthorized' });
      return;
    }
    const provider = req.params.provider;
    if (!PROVIDERS.has(provider)) {
      reply.code(404).send({ error: 'unknown_provider' });
      return;
    }
    let target;
    try {
      target = resolveTarget(provider, `/${req.params['*'] ?? ''}`, req.headers['x-pp-base-url']);
    } catch {
      reply.code(403).send({ error: 'blocked' });
      return;
    }

    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k.toLowerCase())) headers[k] = v;

    const controller = new AbortController();
    req.raw.on('close', () => controller.abort());
    const t0 = Date.now();

    let upstream;
    try {
      upstream = await fetch(target, { method: 'POST', headers, body: JSON.stringify(req.body ?? {}), signal: controller.signal });
    } catch {
      reply.code(502).send({ error: 'upstream_unreachable' });
      return;
    }

    reply.code(upstream.status);
    const ct = upstream.headers.get('content-type');
    if (ct) reply.header('content-type', ct);
    const ra = upstream.headers.get('retry-after');
    if (ra) reply.header('retry-after', ra);
    reply.header('cache-control', 'no-cache');

    // Log métadonnées SEULES (jamais la clé).
    console.log(safeLogLine({ ts: t0, provider, status: upstream.status, ms: Date.now() - t0, bytes: 0 }));

    if (!upstream.body) {
      reply.send('');
      return;
    }
    // Pipe le ReadableStream web → Node stream → reply (pass-through, jamais de .text()).
    return reply.send(Readable.fromWeb(upstream.body));
  });
}
