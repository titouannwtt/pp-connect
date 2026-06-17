// Serveurs MCP remote AUTORISÉS (vendor-officiels uniquement). Le navigateur ne fournit JAMAIS une URL MCP
// arbitraire → le relais ne parle qu'à cette liste fermée (anti-SSRF : le VPS héberge d'autres services en prod).
// Ajouter un serveur = ajouter une entrée ici (clé stable côté front).
const MCP_SERVERS = {
  notion: 'https://mcp.notion.com/mcp',
  github: 'https://api.githubcopilot.com/mcp/',
  linear: 'https://mcp.linear.app/mcp',
  sentry: 'https://mcp.sentry.dev/mcp',
  // Étendre prudemment : uniquement des serveurs MCP remote officiels en HTTPS.
};

// Résout une CLÉ de serveur (ex. 'notion') vers son URL. Lève si la clé n'est pas dans l'allowlist.
export function resolveMcpServer(key) {
  const url = typeof key === 'string' ? MCP_SERVERS[key] : undefined;
  if (!url) throw new Error('MCP_SERVER_NOT_ALLOWED');
  // Garde-fou défense-en-profondeur : l'URL embarquée doit rester HTTPS et sans credentials.
  const u = new URL(url);
  if (u.protocol !== 'https:' || u.username || u.password) throw new Error('MCP_SERVER_NOT_ALLOWED');
  return url;
}

export function listMcpServers() {
  return Object.keys(MCP_SERVERS);
}

export function isAllowedMcpServer(key) {
  return typeof key === 'string' && Object.prototype.hasOwnProperty.call(MCP_SERVERS, key);
}
