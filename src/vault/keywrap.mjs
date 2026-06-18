import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// Durcissement du mode GÉRÉ (KMS-style). La clé de données par-utilisateur n'est PLUS stockée en clair dans
// Supabase : elle est CHIFFRÉE (AES-256-GCM) par une clé maître détenue UNIQUEMENT par le relais (env, hors base).
// AAD = user_id → une clé enveloppée ne peut être déchiffrée que pour SON propriétaire (un blob d'un autre user,
// volé via une fuite Supabase, échoue à l'unwrap). Résultat : une fuite Supabase SEULE n'expose aucune clé.
//
// Format du blob enveloppé (base64) : iv(12) | ciphertext(32) | tag(16).

function key32(b64) {
  if (!b64) return null;
  try {
    const k = Buffer.from(b64, 'base64');
    return k.length === 32 ? k : null;
  } catch {
    return null;
  }
}
function masterKey() {
  return key32(process.env.PP_VAULT_MASTER_KEY);
}
// Clé maître PRÉCÉDENTE (rotation) : `wrap` utilise toujours la clé courante ; `unwrap` retente avec l'ancienne
// → on peut tourner PP_VAULT_MASTER_KEY (nouvelle = courante, ancienne = PREVIOUS) sans casser les coffres Géré
// existants, le temps qu'ils soient ré-enveloppés.
function previousKey() {
  return key32(process.env.PP_VAULT_MASTER_KEY_PREVIOUS);
}

export function vaultEnabled() {
  return masterKey() !== null;
}

// Nouvelle clé de données aléatoire (base64), à utiliser côté client comme clé AES du coffre.
export function newDataKey() {
  return randomBytes(32).toString('base64');
}

export function wrapKey(rawKeyB64, userId) {
  const mk = masterKey();
  if (!mk) throw new Error('vault_master_unset');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', mk, iv);
  cipher.setAAD(Buffer.from(String(userId), 'utf8'));
  const ct = Buffer.concat([cipher.update(Buffer.from(rawKeyB64, 'base64')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]).toString('base64');
}

function tryUnwrap(mk, wrappedB64, userId) {
  const buf = Buffer.from(wrappedB64, 'base64');
  if (buf.length < 12 + 16 + 1) throw new Error('bad_blob');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', mk, iv);
  decipher.setAAD(Buffer.from(String(userId), 'utf8'));
  decipher.setAuthTag(tag);
  const raw = Buffer.concat([decipher.update(ct), decipher.final()]); // throw si AAD/tag invalide
  return raw.toString('base64');
}

export function unwrapKey(wrappedB64, userId) {
  const keys = [masterKey(), previousKey()].filter(Boolean);
  if (!keys.length) throw new Error('vault_master_unset');
  let lastErr = new Error('unwrap_failed');
  for (const mk of keys) {
    try {
      return tryUnwrap(mk, wrappedB64, userId); // courante d'abord, puis l'ancienne (rotation)
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}
