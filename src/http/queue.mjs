// File d'attente GLOBALE du rendu JS : un seul rendu Chromium à la fois sur toute la machine (concurrence = 1).
// Les clients en attente reçoivent leur position (qui décroît en direct). Le slot unique est TOUJOURS libéré
// (succès, erreur, timeout, déconnexion) dans un `finally`. `render` est injecté → testable sans Chromium.

const DEFAULTS = { maxQueueLen: 8, maxWaitMs: 60000 };

function mapErr(message) {
  if (/SSRF/.test(message)) return 'ssrf_blocked';
  if (/WEB_BAD_URL/.test(message)) return 'web_bad_url';
  if (/WEB_UNAVAILABLE/.test(message)) return 'web_unavailable';
  if (/WEB_TIMEOUT|Timeout|timeout/.test(message)) return 'web_timeout';
  if (/WEB_CANCELLED/.test(message)) return 'cancelled';
  return 'render_failed';
}

function safeSend(socket, msg) {
  try {
    if (socket && socket.readyState === 1) socket.send(JSON.stringify(msg));
  } catch {
    /* socket mort */
  }
}

// `render(url, signal)` → Promise<{status,title,html}>. Annulation via le signal (ferme le contexte Playwright).
export function createRenderQueue({ render, maxQueueLen = DEFAULTS.maxQueueLen, maxWaitMs = DEFAULTS.maxWaitMs } = {}) {
  const fifo = []; // entrées en attente (FIFO)
  const byClient = new Map(); // clientKey → entrée (1 seule entrée active par client)
  let slotBusy = false;
  let activeEntry = null;
  let concurrentPeak = 0;
  let concurrent = 0;

  function broadcast() {
    fifo.forEach((e, i) => safeSend(e.socket, { type: 'position', position: i + 1, total: fifo.length }));
  }

  function cleanup(entry) {
    if (entry.waitTimer) {
      clearTimeout(entry.waitTimer);
      entry.waitTimer = null;
    }
    if (byClient.get(entry.clientKey) === entry) byClient.delete(entry.clientKey);
  }

  async function runNext() {
    if (slotBusy) return;
    const entry = fifo.shift();
    if (!entry) return;
    slotBusy = true;
    activeEntry = entry;
    entry.state = 'active';
    if (entry.waitTimer) {
      clearTimeout(entry.waitTimer);
      entry.waitTimer = null;
    }
    safeSend(entry.socket, { type: 'active' });
    broadcast();
    concurrent++;
    concurrentPeak = Math.max(concurrentPeak, concurrent);
    try {
      const result = await render(entry.url, entry.abort.signal);
      safeSend(entry.socket, { type: 'result', ...result });
    } catch (err) {
      safeSend(entry.socket, { type: 'error', code: mapErr(String(err && err.message)) });
    } finally {
      concurrent--;
      slotBusy = false;
      activeEntry = null;
      cleanup(entry);
      try {
        entry.socket.close(1000);
      } catch {
        /* déjà fermé */
      }
      void runNext();
      broadcast();
    }
  }

  // Inscription d'un client. Renvoie l'entrée (pour l'éviction à la déconnexion) ou null si refusé.
  function enqueue({ socket, url, clientKey }) {
    if (byClient.has(clientKey)) {
      safeSend(socket, { type: 'queue_busy' });
      return null;
    }
    if (fifo.length >= maxQueueLen) {
      safeSend(socket, { type: 'queue_full' });
      return null;
    }
    const entry = { socket, url, clientKey, state: 'waiting', abort: new AbortController(), waitTimer: null };
    entry.waitTimer = setTimeout(() => {
      // Attente trop longue sans être servi → on évince proprement.
      const i = fifo.indexOf(entry);
      if (i >= 0) fifo.splice(i, 1);
      cleanup(entry);
      safeSend(entry.socket, { type: 'error', code: 'queue_timeout' });
      try {
        entry.socket.close(1000);
      } catch {
        /* déjà fermé */
      }
      broadcast();
    }, maxWaitMs);
    fifo.push(entry);
    byClient.set(clientKey, entry);
    broadcast();
    void runNext();
    return entry;
  }

  // Le client a disparu (onglet fermé / reload / réseau perdu). En attente → on retire ; actif → on annule le
  // rendu (le `finally` de runNext libère le slot et promeut le suivant).
  function onDisconnect(entry) {
    if (!entry) return;
    if (entry.state === 'active') {
      entry.abort.abort();
      return;
    }
    const i = fifo.indexOf(entry);
    if (i >= 0) fifo.splice(i, 1);
    cleanup(entry);
    broadcast();
  }

  return {
    enqueue,
    onDisconnect,
    // pour les tests
    _peak: () => concurrentPeak,
    _state: () => ({ queued: fifo.length, slotBusy, active: activeEntry?.clientKey ?? null }),
  };
}
