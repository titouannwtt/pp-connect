// Client MCP "Streamable HTTP" minimal (spec 2025), STATELESS : une exécution = initialize → notifications/initialized
// → tools/call (ou tools/list), le tout en mémoire le temps de la requête. Aucun token persisté/loggé.
// Parsing des réponses : JSON unique OU flux SSE (event-stream). Le token (OAuth utilisateur) vient du navigateur.

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'pp-relay', version: '1' };

// Parse un flux SSE en liste de messages JSON-RPC (lignes `data:` concaténées par event).
export function parseSse(text) {
  const out = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).replace(/^\s/, ''))
      .join('\n');
    if (!data) continue;
    try {
      out.push(JSON.parse(data));
    } catch {
      /* event non-JSON (ping…) → ignoré */
    }
  }
  return out;
}

// Extrait le texte d'un résultat tools/call MCP ({ content: [{type:'text', text}], ... }).
export function extractText(result) {
  if (!result) return '';
  const content = Array.isArray(result.content) ? result.content : [];
  const parts = content.filter((c) => c && c.type === 'text' && typeof c.text === 'string').map((c) => c.text);
  if (parts.length) return parts.join('\n');
  // Repli : sérialise structuredContent / le résultat brut.
  if (result.structuredContent !== undefined) return JSON.stringify(result.structuredContent, null, 2);
  return JSON.stringify(result, null, 2);
}

// Un aller-retour JSON-RPC. Renvoie { message, sessionId }. message = la réponse correspondant à body.id (si id).
async function rpc(url, { token, sessionId, body }, fetchImpl) {
  const headers = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': PROTOCOL_VERSION,
  };
  if (token) headers.authorization = `Bearer ${token}`;
  if (sessionId) headers['mcp-session-id'] = sessionId;

  const res = await fetchImpl(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const nextSession = res.headers.get('mcp-session-id') || sessionId || null;

  if (body.id === undefined) return { message: null, sessionId: nextSession }; // notification : pas de réponse attendue

  const ct = (res.headers.get('content-type') || '').toLowerCase();
  const text = await res.text();
  let message = null;
  if (ct.includes('text/event-stream')) {
    const events = parseSse(text);
    message = events.find((e) => e.id === body.id && (e.result !== undefined || e.error !== undefined)) ?? events[events.length - 1] ?? null;
  } else if (text) {
    message = JSON.parse(text);
  }
  if (!res.ok && !message) throw new Error(`MCP_HTTP_${res.status}`);
  return { message, sessionId: nextSession };
}

async function handshake(url, token, fetchImpl) {
  const init = await rpc(
    url,
    { token, body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO } } },
    fetchImpl,
  );
  if (init.message?.error) throw new Error('MCP_INIT_ERROR');
  const sessionId = init.sessionId;
  await rpc(url, { token, sessionId, body: { jsonrpc: '2.0', method: 'notifications/initialized' } }, fetchImpl);
  return sessionId;
}

// Liste les outils d'un serveur MCP.
export async function mcpList({ url, token }, fetchImpl = fetch) {
  const sessionId = await handshake(url, token, fetchImpl);
  const r = await rpc(url, { token, sessionId, body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} } }, fetchImpl);
  if (r.message?.error) throw new Error('MCP_LIST_ERROR');
  const tools = Array.isArray(r.message?.result?.tools) ? r.message.result.tools : [];
  return tools.map((t) => ({ name: t.name, description: t.description ?? '' }));
}

// Appelle un outil et renvoie son texte.
export async function mcpExec({ url, token, tool, args }, fetchImpl = fetch) {
  const sessionId = await handshake(url, token, fetchImpl);
  const r = await rpc(
    url,
    { token, sessionId, body: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: tool, arguments: args || {} } } },
    fetchImpl,
  );
  if (r.message?.error) throw new Error(r.message.error?.message ? `MCP_TOOL_ERROR` : 'MCP_TOOL_ERROR');
  const result = r.message?.result;
  if (result?.isError) throw new Error('MCP_TOOL_ERROR');
  return extractText(result);
}
