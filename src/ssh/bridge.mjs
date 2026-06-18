import { Client } from 'ssh2';
import { randomBytes } from 'node:crypto';
import { assertSafeHost } from '../security/denylist.mjs';

export function newConnId() {
  return randomBytes(16).toString('hex'); // ≥128 bits non devinable (audit 04 §6.3)
}

// Passthrough binaire PUR WS↔SSH (audit 04 §6.1-6.3). Zéro persistance, zéro log de contenu, secrets
// effacés post-handshake. 1 socket = 1 ssh2.Client = 1 connId, aucun état partagé.
export function handleSshConnection(ws, connId, authPromise = Promise.resolve()) {
  let sshClient = null;
  let stream = null;
  let started = false;

  ws.on('message', async (raw, isBinary) => {
    if (stream) {
      if (isBinary) stream.write(raw);
      else {
        try {
          const m = JSON.parse(raw.toString());
          if (m.type === 'resize') stream.setWindow(m.rows, m.cols, 0, 0);
        } catch {
          /* trame de contrôle invalide → ignorer */
        }
      }
      return;
    }
    if (started) return; // init déjà en cours de traitement
    started = true;
    // Le listener est attaché DÈS l'ouverture (pas de course) ; on vérifie le jeton AVANT de traiter l'init.
    try {
      await authPromise;
    } catch {
      ws.close(4401);
      return;
    }
    let init;
    try {
      init = JSON.parse(raw.toString());
    } catch {
      ws.close(4400);
      return;
    }
    if (init.type !== 'init' || typeof init.host !== 'string') {
      ws.close(4400);
      return;
    }
    const port = Number(init.port) || 22;
    if (port < 1 || port > 65535) {
      ws.close(4400);
      return;
    }
    let targetIp;
    try {
      targetIp = await assertSafeHost(init.host); // anti-SSRF AVANT toute connexion
    } catch {
      try {
        ws.send(JSON.stringify({ type: 'error', code: 'SSRF_BLOCKED' }));
      } catch {
        /* socket déjà fermé */
      }
      ws.close(4403);
      return;
    }

    const auth = init.auth || {};
    sshClient = new Client();
    sshClient.on('ready', () => {
      sshClient.shell({ cols: init.cols || 80, rows: init.rows || 24, term: 'xterm-256color' }, (err, sh) => {
        if (err) {
          ws.close();
          return;
        }
        stream = sh;
        try {
          ws.send(JSON.stringify({ type: 'ready', connId }));
        } catch {
          /* socket fermé */
        }
        sh.on('data', (d) => {
          if (ws.readyState === 1) ws.send(d);
        });
        sh.on('close', () => ws.close());
      });
      // Effacement best-effort des secrets post-handshake (P1-3, sans survendre — GC non maîtrisable).
      if (Buffer.isBuffer(auth.privateKey)) auth.privateKey.fill(0);
      auth.password = '';
    });
    sshClient.on('error', (err) => {
      // Échec d'auth (mauvais mot de passe / clé) → code dédié pour un message clair côté client ; sinon générique.
      const code = err && err.level === 'client-authentication' ? 'AUTH_FAILED' : 'SSH_ERROR';
      try {
        ws.send(JSON.stringify({ type: 'error', code }));
      } catch {
        /* socket fermé */
      }
      ws.close();
    });
    sshClient.on('close', () => {
      if (ws.readyState === 1) ws.close();
    });
    sshClient.connect({
      host: targetIp, // connexion par IP vérifiée (anti DNS-rebinding)
      port,
      username: init.user,
      password: auth.password,
      privateKey: auth.privateKey,
      passphrase: auth.passphrase,
      readyTimeout: 15000,
      keepaliveInterval: 20000, // anti-coupure NAT/idle : ping SSH applicatif
      keepaliveCountMax: 3,
      hostHash: 'sha256',
      hostVerifier: () => true, // fingerprint exposé ; validation TOFU côté client (phase 12)
    });
  });

  ws.on('close', () => {
    try {
      stream?.end();
    } catch {
      /* déjà fermé */
    }
    try {
      sshClient?.end();
    } catch {
      /* déjà fermé */
    }
    sshClient = null;
    stream = null;
  });
}
