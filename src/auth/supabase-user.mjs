// Vérifie le porteur d'un access-token Supabase SANS le JWT secret : on demande à Supabase `/auth/v1/user`
// (clé anon publique + token). Si le token est valide, Supabase renvoie l'utilisateur → on récupère un user_id
// DE CONFIANCE (impossible à usurper sans un token valide). Utilisé pour lier l'enveloppe de clé (AAD) à son
// propriétaire dans le mode Géré durci.

export async function verifySupabaseUser(accessToken) {
  if (!accessToken) return null;
  const url = process.env.SUPABASE_URL;
  const anon = process.env.SUPABASE_ANON_KEY;
  if (!url || !anon) return null;
  try {
    const res = await fetch(`${url}/auth/v1/user`, {
      headers: { Authorization: `Bearer ${accessToken}`, apikey: anon },
    });
    if (!res.ok) return null;
    const user = await res.json();
    return typeof user?.id === 'string' ? user.id : null;
  } catch {
    return null;
  }
}
