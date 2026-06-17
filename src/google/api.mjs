// Adaptateur Google (OAuth 2.0 + Drive). URLs FIXES (oauth2.googleapis.com / www.googleapis.com) → pas de SSRF.
// Le client_secret est SERVEUR (env relais) ; les tokens utilisateur viennent du navigateur, utilisés puis
// oubliés (zéro log, zéro persistance). Échange/refresh côté relais (le secret ne touche jamais le navigateur).
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const DRIVE_API = 'https://www.googleapis.com/drive/v3';

// Échange le code OAuth contre access_token (+ refresh_token). code_verifier = PKCE (défense en profondeur).
export async function exchangeGoogleCode({ clientId, clientSecret, code, codeVerifier, redirectUri }, fetchImpl = fetch) {
  const body = new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code' });
  if (codeVerifier) body.set('code_verifier', codeVerifier);
  const res = await fetchImpl(TOKEN_URL, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) throw new Error('GOOGLE_EXCHANGE_FAILED');
  return { accessToken: data.access_token, refreshToken: data.refresh_token ?? '', expiresIn: Number(data.expires_in) || 0, scope: data.scope ?? '' };
}

// Renouvelle l'access_token à partir du refresh_token (le refresh_token, lui, ne change pas).
export async function refreshGoogleToken({ clientId, clientSecret, refreshToken }, fetchImpl = fetch) {
  const body = new URLSearchParams({ client_id: clientId, client_secret: clientSecret, refresh_token: refreshToken, grant_type: 'refresh_token' });
  const res = await fetchImpl(TOKEN_URL, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) throw new Error('GOOGLE_REFRESH_FAILED');
  return { accessToken: data.access_token, expiresIn: Number(data.expires_in) || 0 };
}

// Liste les fichiers Drive (recherche par nom optionnelle). Renvoie de quoi afficher + ouvrir (webViewLink).
export async function driveListFiles({ token, query, pageToken }, fetchImpl = fetch) {
  const q = query && String(query).trim() ? `name contains '${String(query).replace(/['\\]/g, '\\$&')}' and trashed=false` : 'trashed=false';
  const params = new URLSearchParams({
    q,
    fields: 'files(id,name,mimeType,modifiedTime,size,webViewLink,iconLink),nextPageToken',
    pageSize: '100',
    orderBy: 'folder,modifiedTime desc',
    supportsAllDrives: 'true',
    includeItemsFromAllDrives: 'true',
  });
  if (pageToken) params.set('pageToken', pageToken);
  const res = await fetchImpl(`${DRIVE_API}/files?${params.toString()}`, { headers: { authorization: `Bearer ${token}` } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error('GOOGLE_DRIVE_ERROR');
  const files = (data.files ?? []).map((f) => ({
    id: f.id ?? '',
    name: f.name ?? '',
    mimeType: f.mimeType ?? '',
    modifiedTime: f.modifiedTime ?? '',
    size: Number(f.size) || 0,
    webViewLink: f.webViewLink ?? '',
    iconLink: f.iconLink ?? '',
  }));
  return { files, nextPageToken: data.nextPageToken ?? '' };
}

// Formats Google natifs → export (pas de téléchargement binaire direct). Le reste : alt=media.
const GOOGLE_EXPORT = {
  'application/vnd.google-apps.document': 'application/pdf',
  'application/vnd.google-apps.presentation': 'application/pdf',
  'application/vnd.google-apps.spreadsheet': 'text/csv',
  'application/vnd.google-apps.drawing': 'image/png',
};

// Flux de téléchargement d'un fichier (alt=media) ou export PDF/CSV pour les Docs/Sheets/Slides. Host fixe.
export async function driveDownload({ token, id, mimeType }, fetchImpl = fetch) {
  const exportMime = GOOGLE_EXPORT[mimeType];
  const url = exportMime
    ? `${DRIVE_API}/files/${encodeURIComponent(id)}/export?mimeType=${encodeURIComponent(exportMime)}`
    : `${DRIVE_API}/files/${encodeURIComponent(id)}?alt=media&supportsAllDrives=true`;
  const res = await fetchImpl(url, { headers: { authorization: `Bearer ${token}` } });
  if (!res.ok || !res.body) throw new Error('GOOGLE_DRIVE_ERROR');
  return { body: res.body, contentType: res.headers.get('content-type') || 'application/octet-stream' };
}
