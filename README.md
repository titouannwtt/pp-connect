# pp-connect (AGPL-3.0-or-later)

**Partie « connexions » du relais stateless de [Prompt Pipeline](https://prompt-pipeline.io).**

Ces modules sont publiés pour la **transparence** : ils manipulent les identifiants que vous utilisez (SSH, IA,
Drive/Notion/GitHub, FTP, MCP) en mode **forward-then-forget**, avec anti-SSRF et un logger qui **rédige** tout
secret. Le reste du relais (orchestration, config, auth) reste fermé.

## Ce que ce dépôt prouve — et ne prouve PAS
- ✅ **Design auditable** : on lit le code qui touche les identifiants et on vérifie l'intention *stateless /
  zéro-log de secret / anti-SSRF*. Le `client_secret`/les tokens ne sont jamais journalisés ni persistés ; ils
  arrivent par paramètre et sont oubliés après usage.
- ❌ **Pas de preuve au runtime** : le binaire qui tourne sur le serveur n'est pas vérifiable à distance (pas de
  TEE). L'assurance vient de ce code ouvert + de la **vérification réseau** côté navigateur (le clair ne va qu'au
  relais → la cible que **vous** utilisez). Voir le claim de confidentialité de Prompt Pipeline.

## Contenu
- `src/proxy.mjs` — proxy IA pass-through (clé transmise au provider, jamais loggée).
- `src/log.mjs` — logger **redacteur** (en-têtes d'auth/clés `[redacted]`, métadonnées seules).
- `src/ssh/`, `src/ftp/` — ponts SSH/SFTP (mot de passe transmis à la cible).
- `src/google/`, `src/notion/`, `src/github/` — échanges OAuth + proxys API.
- `src/mcp/` — proxy MCP allowlisté. `src/http/` — client HTTP + rendu web. `src/security/` — anti-SSRF + Origin.

## Note source / runtime
Ce dépôt est un **miroir d'audit** du code de connexion du relais (le secret de l'app — ex. `client_secret`
Google — vit dans l'environnement du serveur, jamais ici). Il n'est pas un serveur autonome (la config et
l'orchestration sont fermées). Synchronisé depuis le relais.

## Licence — open-core
AGPL : un tiers qui réutilise pp-connect dans un service réseau doit publier sa source. Le détenteur du copyright
n'est pas lié par sa propre AGPL (peut l'utiliser dans un relais fermé). L'AGPL sert à **dissuader la reprise**.
