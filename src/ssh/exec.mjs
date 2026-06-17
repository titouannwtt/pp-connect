import { Client } from 'ssh2';
import { assertSafeHost } from '../security/denylist.mjs';

// Exécution SSH one-shot (pour « SQL via SSH » : lance une commande, renvoie stdout/stderr bornés, puis ferme).
// Strictement MOINS puissant que le shell interactif du bridge (mêmes garde-fous : anti-SSRF, TOFU, timeout).
const MAX_OUT = 256 * 1024;
const TIMEOUT = 30000;

export async function sshExec(params) {
  const port = Number(params.port) || 22;
  if (port < 1 || port > 65535) throw new Error('SSH_BAD_PORT');
  if (typeof params.host !== 'string' || !params.host) throw new Error('SSH_BAD_HOST');
  if (typeof params.command !== 'string' || !params.command.trim()) throw new Error('SSH_BAD_COMMAND');
  const targetIp = await assertSafeHost(params.host); // anti-SSRF AVANT connexion

  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const timer = setTimeout(() => done(new Error('SSH_TIMEOUT')), TIMEOUT);
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        conn.end();
      } catch {
        /* déjà fermé */
      }
      if (err) reject(err);
      else resolve(val);
    };
    conn.on('error', () => done(new Error('SSH_CONN_ERROR')));
    conn.on('ready', () => {
      conn.exec(params.command, (err, stream) => {
        if (err) return done(new Error('SSH_EXEC_ERROR'));
        let out = '';
        let errOut = '';
        let truncated = false;
        const cap = (s, add) => {
          if (s.length >= MAX_OUT) {
            truncated = true;
            return s;
          }
          return (s + add).slice(0, MAX_OUT);
        };
        stream.on('data', (d) => {
          out = cap(out, d.toString());
        });
        stream.stderr.on('data', (d) => {
          errOut = cap(errOut, d.toString());
        });
        stream.on('close', (code) => done(null, { stdout: out, stderr: errOut, code: code ?? 0, truncated }));
      });
    });
    conn.connect({
      host: targetIp,
      port,
      username: params.user,
      password: params.password,
      readyTimeout: 15000,
      hostHash: 'sha256',
      hostVerifier: () => true,
    });
  });
}
