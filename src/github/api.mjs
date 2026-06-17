// Adaptateur GitHub (API REST). Hôte FIXE api.github.com → pas de SSRF. Le repo est validé (owner/name) pour
// éviter toute injection de chemin. Le token (PAT, optionnel) vient du navigateur, utilisé puis oublié (zéro log).
const API = 'https://api.github.com';
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function ghHeaders(token) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'pp-relay', 'x-github-api-version': '2022-11-28' };
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

function clampPer(perPage) {
  return String(Math.min(Math.max(Number(perPage) || 30, 1), 100));
}

function clampPage(page) {
  return String(Math.max(Number(page) || 1, 1));
}

export async function githubCommits({ repo, branch, token, perPage, page }, fetchImpl = fetch) {
  if (!REPO_RE.test(repo || '')) throw new Error('GITHUB_BAD_REPO');
  const params = new URLSearchParams({ per_page: clampPer(perPage), page: clampPage(page) });
  if (branch) params.set('sha', branch);
  const res = await fetchImpl(`${API}/repos/${repo}/commits?${params.toString()}`, { headers: ghHeaders(token) });
  if (!res.ok) throw new Error(`GITHUB_${res.status}`);
  const data = await res.json();
  return (Array.isArray(data) ? data : []).map((c) => ({
    sha: typeof c.sha === 'string' ? c.sha.slice(0, 7) : '',
    message: (c.commit?.message ?? '').split('\n')[0],
    author: c.commit?.author?.name ?? c.author?.login ?? '',
    avatar: c.author?.avatar_url ?? '',
    date: c.commit?.author?.date ?? '',
    url: c.html_url ?? '',
  }));
}

const STATE_RE = /^(open|closed|all)$/;

export async function githubPulls({ repo, token, state, perPage, page }, fetchImpl = fetch) {
  if (!REPO_RE.test(repo || '')) throw new Error('GITHUB_BAD_REPO');
  const st = STATE_RE.test(state || '') ? state : 'open';
  const params = new URLSearchParams({ state: st, per_page: clampPer(perPage), page: clampPage(page), sort: 'updated', direction: 'desc' });
  const res = await fetchImpl(`${API}/repos/${repo}/pulls?${params.toString()}`, { headers: ghHeaders(token) });
  if (!res.ok) throw new Error(`GITHUB_${res.status}`);
  const data = await res.json();
  return (Array.isArray(data) ? data : []).map((p) => ({
    number: p.number ?? 0,
    title: p.title ?? '',
    author: p.user?.login ?? '',
    avatar: p.user?.avatar_url ?? '',
    date: p.updated_at ?? '',
    url: p.html_url ?? '',
    state: p.draft ? 'draft' : (p.state ?? 'open'),
  }));
}

export async function githubIssues({ repo, token, state, perPage, page }, fetchImpl = fetch) {
  if (!REPO_RE.test(repo || '')) throw new Error('GITHUB_BAD_REPO');
  const st = STATE_RE.test(state || '') ? state : 'open';
  const params = new URLSearchParams({ state: st, per_page: clampPer(perPage), page: clampPage(page), sort: 'updated', direction: 'desc' });
  const res = await fetchImpl(`${API}/repos/${repo}/issues?${params.toString()}`, { headers: ghHeaders(token) });
  if (!res.ok) throw new Error(`GITHUB_${res.status}`);
  const data = await res.json();
  // L'endpoint issues renvoie AUSSI les PR → on les exclut (présence de pull_request).
  return (Array.isArray(data) ? data : [])
    .filter((i) => !i.pull_request)
    .map((i) => ({
      number: i.number ?? 0,
      title: i.title ?? '',
      author: i.user?.login ?? '',
      avatar: i.user?.avatar_url ?? '',
      date: i.updated_at ?? '',
      url: i.html_url ?? '',
      state: i.state ?? 'open',
      comments: i.comments ?? 0,
    }));
}
