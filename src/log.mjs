// Logger FILTRÉ : jamais de clé/header d'auth/body (audit 04 §6.2/§7.1). Logs = métadonnées seules.
const SENSITIVE = new Set(['authorization', 'x-api-key', 'x-goog-api-key', 'x-pp-token', 'x-pp-base-url', 'cookie', 'set-cookie']);

export function redactHeaders(headers) {
  const out = {};
  for (const key of Object.keys(headers || {})) {
    out[key.toLowerCase()] = SENSITIVE.has(key.toLowerCase()) ? '[redacted]' : headers[key];
  }
  return out;
}

// Sérialise UNIQUEMENT les champs sûrs (même si meta en contient d'autres).
export function safeLogLine(meta) {
  return JSON.stringify({ ts: meta.ts, provider: meta.provider, status: meta.status, ms: meta.ms, bytes: meta.bytes });
}
