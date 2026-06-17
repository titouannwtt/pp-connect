// Vérif Origin stricte (anti-CSWSH : un WebSocket n'est protégé NI par la SOP NI par CORS — audit 04 §6.4).
export function isAllowedOrigin(origin, allowed) {
  return typeof origin === 'string' && allowed.includes(origin);
}
