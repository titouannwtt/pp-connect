import { assertSafeHost } from '../security/denylist.mjs';

// Rendu de page avec JavaScript via Chromium/Playwright (lazy → le relais démarre sans Chromium installé : la
// route renvoie alors WEB_UNAVAILABLE et le front retombe sur le fetch léger).
//
// SÉCURITÉ : anti-SSRF sur l'URL principale ET chaque sous-requête (le VPS héberge d'autres services).
// PERFORMANCE (petit VPS partagé) : UN SEUL rendu à la fois (concurrence = 1), hard-timeout global, navigateur
// singleton recyclé (anti-fuite mémoire), ressources lourdes coupées, contexte jetable annulable (abort).

const RENDER_CONCURRENCY = 1;
const NAV_TIMEOUT = 15000;
const RENDER_HARD_TIMEOUT_MS = 20000; // borne TOTALE (goto + hydrate + content + title)
const HYDRATE_WAIT = 1200;
const MAX_HTML = 2 * 1024 * 1024;
const BROWSER_MAX_RENDERS = 30; // recyclage par nombre de rendus
const BROWSER_TTL_MS = 15 * 60 * 1000; // recyclage par âge
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

const CHROMIUM_ARGS = [
  '--no-sandbox',
  '--disable-dev-shm-usage',
  '--disable-gpu',
  '--single-process', // concurrence = 1 → 1 seul process (moins de RAM/threads)
  '--no-zygote',
  '--disable-extensions',
  '--disable-background-networking',
  '--disable-renderer-backgrounding',
  '--disable-features=site-per-process,IsolateOrigins',
  '--js-flags=--max-old-space-size=256',
];

let browserPromise = null;
let renderCount = 0;
let launchedAt = 0;
let active = 0;

async function getBrowser() {
  if (browserPromise) return browserPromise;
  browserPromise = (async () => {
    const { chromium } = await import('playwright'); // throw si non installé → capté par la route
    const b = await chromium.launch({ headless: true, args: CHROMIUM_ARGS });
    renderCount = 0;
    launchedAt = Date.now();
    b.on('disconnected', () => {
      browserPromise = null;
    });
    return b;
  })().catch((err) => {
    browserPromise = null;
    throw err;
  });
  return browserPromise;
}

// Recyclage : on ferme le navigateur quand le slot est libre et qu'il a trop servi / trop vieilli. Au prochain
// rendu il est relancé en lazy. On ferme le NAVIGATEUR seulement ici (jamais à l'annulation d'un rendu).
async function maybeRecycle() {
  if (active > 0 || !browserPromise) return;
  const tooMany = renderCount >= BROWSER_MAX_RENDERS;
  const tooOld = launchedAt && Date.now() - launchedAt > BROWSER_TTL_MS;
  if (!tooMany && !tooOld) return;
  const b = await browserPromise.catch(() => null);
  browserPromise = null;
  if (b) await b.close().catch(() => {});
}

function withTimeout(promise, ms, code) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(code)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export function renderConcurrency() {
  return RENDER_CONCURRENCY;
}

export async function renderPage({ url, signal }) {
  let target;
  try {
    target = new URL(String(url));
  } catch {
    throw new Error('WEB_BAD_URL');
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error('WEB_BAD_URL');
  await assertSafeHost(target.hostname); // anti-SSRF sur l'URL principale

  if (active >= RENDER_CONCURRENCY) throw new Error('WEB_BUSY');
  if (signal?.aborted) throw new Error('WEB_CANCELLED');
  active++;

  let browser;
  try {
    browser = await getBrowser().catch(() => {
      throw new Error('WEB_UNAVAILABLE');
    });
    const ctx = await browser.newContext({ userAgent: UA, javaScriptEnabled: true, serviceWorkers: 'block' });
    ctx.setDefaultNavigationTimeout(NAV_TIMEOUT);

    // Annulation : fermer le CONTEXTE (jetable) fait rejeter goto/content en attente → libère le slot.
    const onAbort = () => {
      ctx.close().catch(() => {});
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    const page = await ctx.newPage();
    const safeCache = new Map();
    await page.route('**/*', async (route) => {
      const req = route.request();
      const type = req.resourceType();
      if (type === 'image' || type === 'media' || type === 'font') return route.abort();
      let host;
      try {
        host = new URL(req.url()).hostname;
      } catch {
        return route.abort();
      }
      let ok = safeCache.get(host);
      if (ok === undefined) {
        try {
          await assertSafeHost(host);
          ok = true;
        } catch {
          ok = false;
        }
        safeCache.set(host, ok);
      }
      return ok ? route.continue() : route.abort();
    });

    try {
      const render = (async () => {
        const resp = await page.goto(target.toString(), { waitUntil: 'domcontentloaded' });
        await page.waitForTimeout(HYDRATE_WAIT);
        const html = (await page.content()).slice(0, MAX_HTML);
        const title = await page.title();
        return { status: resp ? resp.status() : 0, title, html };
      })();
      return await withTimeout(render, RENDER_HARD_TIMEOUT_MS, 'WEB_TIMEOUT');
    } finally {
      if (signal) signal.removeEventListener('abort', onAbort);
      await ctx.close().catch(() => {});
    }
  } finally {
    active--;
    renderCount++;
    await maybeRecycle();
  }
}
