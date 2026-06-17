// Adaptateur Notion (OAuth public classique + API REST). URLs FIXES (api.notion.com) → pas de SSRF.
// Le token (access_token de l'utilisateur) vient du navigateur, utilisé puis oublié (zéro log, zéro persistance).
const TOKEN_URL = 'https://api.notion.com/v1/oauth/token';
const API_BASE = 'https://api.notion.com/v1';
const NOTION_VERSION = '2022-06-28';

// Échange le code OAuth contre un access_token (Basic auth = base64(client_id:client_secret)).
export async function exchangeNotionCode({ clientId, clientSecret, code, redirectUri }, fetchImpl = fetch) {
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const res = await fetchImpl(TOKEN_URL, {
    method: 'POST',
    headers: { authorization: `Basic ${basic}`, 'content-type': 'application/json', 'notion-version': NOTION_VERSION },
    body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) throw new Error('NOTION_EXCHANGE_FAILED');
  return { token: data.access_token, workspace: data.workspace_name ?? '' };
}

function notionTitle(obj) {
  try {
    if (obj.object === 'database') return (obj.title ?? []).map((t) => t.plain_text ?? '').join('');
    const props = obj.properties ?? {};
    for (const k of Object.keys(props)) {
      const p = props[k];
      if (p && p.type === 'title') return (p.title ?? []).map((t) => t.plain_text ?? '').join('');
    }
    return obj.id ?? '';
  } catch {
    return '';
  }
}

// Exécute une opération Notion. v1 : 'search' → liste les titres des pages/bases accessibles.
export async function notionExec({ token, op, args }, fetchImpl = fetch) {
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'notion-version': NOTION_VERSION };
  const a = args || {};
  if (!op || op === 'search') {
    const body = { query: typeof a.query === 'string' ? a.query : '', page_size: Math.min(Number(a.limit) || 50, 100) };
    if (a.type === 'page' || a.type === 'database') body.filter = { property: 'object', value: a.type };
    const res = await fetchImpl(`${API_BASE}/search`, { method: 'POST', headers, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error('NOTION_API_ERROR');
    const titles = (data.results ?? []).map((r) => notionTitle(r)).filter(Boolean);
    return titles.join('\n');
  }
  throw new Error('NOTION_OP_UNKNOWN');
}

// Recherche structurée (pour le panneau Notion) : renvoie {id, title, url} par page/base.
export async function notionSearch({ token, query, limit }, fetchImpl = fetch) {
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'notion-version': NOTION_VERSION };
  const body = { query: typeof query === 'string' ? query : '', page_size: Math.min(Number(limit) || 50, 100) };
  const res = await fetchImpl(`${API_BASE}/search`, { method: 'POST', headers, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error('NOTION_API_ERROR');
  return (data.results ?? []).map((r) => ({ id: r.id ?? '', title: notionTitle(r) || '(sans titre)', url: r.url ?? '' }));
}

function richText(arr) {
  return (Array.isArray(arr) ? arr : []).map((r) => r.plain_text ?? '').join('');
}

function blockToText(b) {
  const type = b.type;
  const o = b[type] ?? {};
  const rt = richText(o.rich_text);
  switch (type) {
    case 'heading_1':
      return `# ${rt}`;
    case 'heading_2':
      return `## ${rt}`;
    case 'heading_3':
      return `### ${rt}`;
    case 'bulleted_list_item':
      return `- ${rt}`;
    case 'numbered_list_item':
      return `1. ${rt}`;
    case 'to_do':
      return `[${o.checked ? 'x' : ' '}] ${rt}`;
    case 'quote':
      return `> ${rt}`;
    case 'code':
      return '```\n' + rt + '\n```';
    case 'divider':
      return '---';
    default:
      return rt;
  }
}

// Contenu texte d'une page Notion (blocs de 1er niveau → markdown léger). pageId = id de page Notion (validé).
const ID_RE = /^[a-f0-9-]{32,36}$/i;
export async function notionPageContent({ token, pageId }, fetchImpl = fetch) {
  if (!ID_RE.test(pageId || '')) throw new Error('NOTION_BAD_ID');
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'notion-version': NOTION_VERSION };
  const res = await fetchImpl(`${API_BASE}/blocks/${pageId}/children?page_size=100`, { headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error('NOTION_API_ERROR');
  return (data.results ?? [])
    .map(blockToText)
    .filter((s) => s !== '')
    .join('\n');
}

export const NOTION_OPS = ['search'];
