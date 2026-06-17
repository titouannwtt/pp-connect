import { Client } from 'ssh2';
import { assertSafeHost } from '../security/denylist.mjs';

// Bridge SFTP stateless (sur SSH, réutilise ssh2). Chaque opération ouvre une connexion vérifiée (anti-SSRF),
// fait l'op, puis ferme. Zéro persistance, zéro log de contenu/secret. Aligné sur le bridge SSH (audit 04).
const MAX_FILE = 512 * 1024; // plafond de lecture/écriture texte (le relais a bodyLimit 1 Mo)
const MEDIA_MAX = 25 * 1024 * 1024; // plafond média (renvoyé en binaire brut, hors limite JSON)

// Types média servis en aperçu (image/audio/vidéo). Détection par extension uniquement.
const MEDIA_MIME = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  bmp: 'image/bmp',
  ico: 'image/x-icon',
  mp3: 'audio/mpeg',
  wav: 'audio/wav',
  ogg: 'audio/ogg',
  oga: 'audio/ogg',
  m4a: 'audio/mp4',
  aac: 'audio/aac',
  flac: 'audio/flac',
  mp4: 'video/mp4',
  m4v: 'video/mp4',
  webm: 'video/webm',
  mov: 'video/quicktime',
  mkv: 'video/x-matroska',
};

export function mediaType(path) {
  const ext = (String(path).split('.').pop() || '').toLowerCase();
  return MEDIA_MIME[ext] || null;
}

async function withSftp(params, fn) {
  const port = Number(params.port) || 22;
  if (port < 1 || port > 65535) throw new Error('FTP_BAD_PORT');
  if (typeof params.host !== 'string' || !params.host) throw new Error('FTP_BAD_HOST');
  const targetIp = await assertSafeHost(params.host); // anti-SSRF AVANT connexion

  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      try {
        conn.end();
      } catch {
        /* déjà fermé */
      }
      if (err) reject(err);
      else resolve(val);
    };
    conn.on('error', () => done(new Error('FTP_CONN_ERROR')));
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return done(new Error('FTP_SFTP_ERROR'));
        Promise.resolve(fn(sftp)).then((v) => done(null, v)).catch((e) => done(e));
      });
    });
    conn.connect({
      host: targetIp,
      port,
      username: params.user,
      password: params.password,
      privateKey: params.privateKey,
      passphrase: params.passphrase,
      readyTimeout: 15000,
      hostHash: 'sha256',
      hostVerifier: () => true, // TOFU côté client comme le SSH
    });
  });
}

function normDir(p) {
  if (typeof p !== 'string' || !p) return '.';
  return p;
}

export async function sftpList(params) {
  const path = normDir(params.path);
  return withSftp(params, (sftp) =>
    new Promise((resolve, reject) => {
      sftp.readdir(path, (err, list) => {
        if (err) return reject(new Error('FTP_LIST_ERROR'));
        const entries = list
          .map((e) => ({
            name: e.filename,
            dir: typeof e.longname === 'string' ? e.longname[0] === 'd' : false,
            size: e.attrs?.size ?? 0,
            mtime: e.attrs?.mtime ? e.attrs.mtime * 1000 : 0,
          }))
          .filter((e) => e.name !== '.' && e.name !== '..')
          .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1));
        resolve({ path, entries });
      });
    }),
  );
}

export async function sftpGet(params) {
  if (typeof params.path !== 'string' || !params.path) throw new Error('FTP_BAD_PATH');
  return withSftp(params, (sftp) =>
    new Promise((resolve, reject) => {
      sftp.stat(params.path, (statErr, st) => {
        if (statErr) return reject(new Error('FTP_STAT_ERROR'));
        if (st.size > MAX_FILE) return reject(new Error('FTP_TOO_LARGE'));
        sftp.readFile(params.path, (err, buf) => {
          if (err) return reject(new Error('FTP_READ_ERROR'));
          resolve({ content: buf.toString('base64'), size: buf.length });
        });
      });
    }),
  );
}

// Lit un fichier média et renvoie ses octets BRUTS + content-type (servi en binaire → pas de base64, pas de
// limite JSON). Plafond 25 Mo. Anti-SSRF via withSftp.
export async function sftpMedia(params) {
  if (typeof params.path !== 'string' || !params.path) throw new Error('FTP_BAD_PATH');
  const contentType = mediaType(params.path);
  if (!contentType) throw new Error('FTP_NOT_MEDIA');
  return withSftp(params, (sftp) =>
    new Promise((resolve, reject) => {
      sftp.stat(params.path, (statErr, st) => {
        if (statErr) return reject(new Error('FTP_STAT_ERROR'));
        if (st.size > MEDIA_MAX) return reject(new Error('FTP_TOO_LARGE'));
        sftp.readFile(params.path, (err, buf) => {
          if (err) return reject(new Error('FTP_READ_ERROR'));
          resolve({ buffer: buf, contentType });
        });
      });
    }),
  );
}

function reqPath(p) {
  if (typeof p !== 'string' || !p) throw new Error('FTP_BAD_PATH');
  return p;
}

export async function sftpStat(params) {
  reqPath(params.path);
  return withSftp(params, (sftp) =>
    new Promise((resolve) => {
      sftp.stat(params.path, (err, st) => {
        if (err) return resolve({ exists: false });
        resolve({ exists: true, dir: st.isDirectory(), size: st.size });
      });
    }),
  );
}

export async function sftpRename(params) {
  reqPath(params.from);
  reqPath(params.to);
  return withSftp(params, (sftp) =>
    new Promise((resolve, reject) => {
      sftp.rename(params.from, params.to, (err) => (err ? reject(new Error('FTP_RENAME_ERROR')) : resolve({ ok: true })));
    }),
  );
}

export async function sftpMkdir(params) {
  reqPath(params.path);
  return withSftp(params, (sftp) =>
    new Promise((resolve, reject) => {
      sftp.mkdir(params.path, (err) => (err ? reject(new Error('FTP_MKDIR_ERROR')) : resolve({ ok: true })));
    }),
  );
}

// Suppression NON récursive : fichier (unlink) ou dossier VIDE (rmdir échoue si non vide → garde-fou).
export async function sftpRm(params) {
  reqPath(params.path);
  return withSftp(params, (sftp) =>
    new Promise((resolve, reject) => {
      const cb = (err) => (err ? reject(new Error('FTP_RM_ERROR')) : resolve({ ok: true }));
      if (params.dir) sftp.rmdir(params.path, cb);
      else sftp.unlink(params.path, cb);
    }),
  );
}

// Aperçu média EN FLUX (streaming) : pas de mise en mémoire ni de plafond → gère les gros fichiers (wav, vidéo).
// La connexion reste ouverte le temps du flux puis se ferme (sur close/error). Anti-SSRF avant connexion.
export async function sftpMediaStream(params) {
  if (typeof params.path !== 'string' || !params.path) throw new Error('FTP_BAD_PATH');
  const contentType = mediaType(params.path);
  if (!contentType) throw new Error('FTP_NOT_MEDIA');
  const port = Number(params.port) || 22;
  if (port < 1 || port > 65535) throw new Error('FTP_BAD_PORT');
  if (typeof params.host !== 'string' || !params.host) throw new Error('FTP_BAD_HOST');
  const targetIp = await assertSafeHost(params.host);

  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const fail = (e) => {
      if (settled) return;
      settled = true;
      try {
        conn.end();
      } catch {
        /* déjà fermé */
      }
      reject(e);
    };
    conn.on('error', () => fail(new Error('FTP_CONN_ERROR')));
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return fail(new Error('FTP_SFTP_ERROR'));
        sftp.stat(params.path, (statErr, st) => {
          if (statErr) return fail(new Error('FTP_STAT_ERROR'));
          const stream = sftp.createReadStream(params.path);
          stream.on('error', () => {
            try {
              conn.end();
            } catch {
              /* déjà fermé */
            }
          });
          stream.on('close', () => {
            try {
              conn.end();
            } catch {
              /* déjà fermé */
            }
          });
          settled = true;
          resolve({ stream, contentType, size: st.size });
        });
      });
    });
    conn.connect({ host: targetIp, port, username: params.user, password: params.password, readyTimeout: 15000, hostHash: 'sha256', hostVerifier: () => true });
  });
}

export async function sftpPut(params) {
  if (typeof params.path !== 'string' || !params.path) throw new Error('FTP_BAD_PATH');
  const enc = params.encoding === 'base64' ? 'base64' : 'utf8';
  const buf = Buffer.from(String(params.content ?? ''), enc);
  if (buf.length > MAX_FILE) throw new Error('FTP_TOO_LARGE');
  return withSftp(params, (sftp) =>
    new Promise((resolve, reject) => {
      sftp.writeFile(params.path, buf, (err) => {
        if (err) return reject(new Error('FTP_WRITE_ERROR'));
        resolve({ ok: true });
      });
    }),
  );
}
