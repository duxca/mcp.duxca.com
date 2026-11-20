// relay チャット画面。持ち主が agent "user" として relay の会話に加わる。
// 認可は公開クライアント（動的登録 + PKCE S256）。アクセストークンはメモリ、リフレッシュトークンは localStorage。
// サーバから来た文字列（本文・名前・件名・ファイル名）は DOM のテキストとしてだけ描く。文字列を HTML として解釈させる API は使わない。

const ME = 'user';
const ORIGIN = location.origin;
const MCP_URL = '/relay/v1';
const RESOURCE = `${ORIGIN}${MCP_URL}`;
const CALLBACK_PATH = '/relay/callback';
const REDIRECT_URI = `${ORIGIN}${CALLBACK_PATH}`;
const MAX_TEXT = 20000;
const MAX_SUBJECT = 200;
const THREAD_LIMIT = 100;
const MAX_QUERY = 200;
const SEARCH_LIMIT = 50;
// 一覧に出す抜粋の一致より前の文字数（サーバは 60 文字まで返す）。後ろは CSS で 3 行に切る
const EXCERPT_BEFORE = 20;
const POLL_WAIT_SECONDS = 55;
const PARTICIPANT_BATCH = 10;
const TIMEOUT_MS = {
  normal: 20000,
  // 宛先の webhook（最大 5 秒）を待ってから返る
  send: 40000,
  poll: (POLL_WAIT_SECONDS + 20) * 1000,
  attachment: 60000,
};
const USER_DESCRIPTION = 'lego 本人。relay の Web チャット画面（/relay/）から参加しています。';
const KEY = {
  client: 'relay-chat.client_id',
  refresh: 'relay-chat.refresh_token',
  participants: 'relay-chat.participants',
  pkce: 'relay-chat.pkce',
};

// ---------------------------------------------------------------------------
// 小道具

class AppError extends Error {
  /** kind: timeout | network | http | rpc | tool | login | aborted */
  constructor(message, kind, extra = {}) {
    super(message);
    this.kind = kind;
    Object.assign(this, extra);
  }
}

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

function base64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(bytes) {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function s256(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

const dateFormat = new Intl.DateTimeFormat('ja-JP', {
  month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit',
});
const clockFormat = new Intl.DateTimeFormat('ja-JP', {
  hour: '2-digit', minute: '2-digit', second: '2-digit',
});

function formatDate(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso ?? '') : dateFormat.format(d);
}

/** 末尾の n 文字にし、切ったら … を付ける。サロゲートペアは割らない。 */
function tail(s, n) {
  const chars = Array.from(s ?? '');
  return chars.length <= n ? chars.join('') : `…${chars.slice(-n).join('')}`;
}

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const idNum = (id) => Number(id) || 0;
const maxId = (messages) => messages.reduce((m, x) => Math.max(m, idNum(x.id)), 0);
const threadHash = (id, messageId) => `#/t/${encodeURIComponent(id)}${messageId ? `?${new URLSearchParams({ m: messageId })}` : ''}`;
const searchHash = (q) => (q ? `#/search?${new URLSearchParams({ q })}` : '#/search');
const threadsHash = (agent) => (agent ? `#/threads?${new URLSearchParams({ agent })}` : '#/threads');
const newHash = (to) => (to ? `#/new?${new URLSearchParams({ to })}` : '#/new');

// ---------------------------------------------------------------------------
// HTTP（すべてタイムアウト付き。本文を読み切るまでを時間に含める）

async function request(url, init, timeoutMs, signal) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const onAbort = () => ctrl.abort();
  if (signal?.aborted) ctrl.abort();
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal, cache: 'no-store', credentials: 'omit' });
    const text = await res.text();
    return { status: res.status, body: parseJson(text) };
  } catch {
    if (signal?.aborted) throw new AppError('中断した', 'aborted');
    if (ctrl.signal.aborted) {
      throw new AppError(`${Math.round(timeoutMs / 1000)} 秒待っても応答が無かった`, 'timeout');
    }
    throw new AppError('サーバに届かなかった（オフラインか通信エラー）', 'network');
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

function httpError(status, body) {
  const detail = body?.error_description || body?.error || '';
  const hint = {
    413: '送る内容が大きすぎる',
    429: '混み合っている。少し待ってから',
    502: 'サーバに繋がらない',
    503: 'サーバが一時的に使えない',
    504: 'サーバの応答が遅すぎた',
  }[status];
  return new AppError(`HTTP ${status}${hint ? `（${hint}）` : ''}${detail ? `: ${detail}` : ''}`, 'http');
}

// ---------------------------------------------------------------------------
// 認可

const auth = { access: null, expiresAt: 0, gen: 0, refreshing: null };
const channel = 'BroadcastChannel' in self ? new BroadcastChannel('relay-chat') : null;

function setAccess(token, expiresAt) {
  auth.access = token;
  auth.expiresAt = expiresAt;
  auth.gen += 1;
}

function storeTokens(t) {
  if (typeof t.refresh_token === 'string') localStorage.setItem(KEY.refresh, t.refresh_token);
  const expiresAt = Date.now() + (Number(t.expires_in) || 3600) * 1000;
  setAccess(t.access_token, expiresAt);
  // 同じブラウザの他のタブも使えるように渡す（refresh の入れ替えでタブどうしが古い組を握り合わないため）
  channel?.postMessage({ type: 'token', access: t.access_token, expiresAt });
}

channel?.addEventListener('message', (ev) => {
  const m = ev.data;
  if (m?.type === 'token' && typeof m.access === 'string') {
    setAccess(m.access, Number(m.expiresAt) || 0);
    if (!S.signedIn && localStorage.getItem(KEY.refresh)) startApp(false);
  } else if (m?.type === 'logout') {
    requireLogin('別のタブでログアウトした。');
  }
});

async function tokenRequest(params) {
  const { status, body } = await request('/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams(params),
  }, TIMEOUT_MS.normal);
  if (status === 200 && typeof body?.access_token === 'string') return body;
  if (body?.error === 'invalid_grant' || body?.error === 'invalid_client') {
    const why = body.error_description ? `（${body.error_description}）` : '';
    throw new AppError(`ログインし直す必要がある${why}`, 'login', { oauthError: body.error });
  }
  throw httpError(status, body);
}

function withTokenLock(fn) {
  // 別のタブと同時に refresh すると、使用済みの refresh を出したことになる
  return navigator.locks?.request ? navigator.locks.request('relay-chat-token', fn) : fn();
}

/** `usedGen` は 401 を受けたときのトークンの世代。既に入れ替わっていれば何もしない。 */
function refresh(usedGen) {
  if (!auth.refreshing) {
    auth.refreshing = withTokenLock(async () => {
      if (auth.access && auth.gen !== usedGen && Date.now() < auth.expiresAt - 30000) return;
      const rt = localStorage.getItem(KEY.refresh);
      const clientId = localStorage.getItem(KEY.client);
      if (!rt || !clientId) throw new AppError('ログインが必要', 'login');
      try {
        storeTokens(await tokenRequest({ grant_type: 'refresh_token', refresh_token: rt, client_id: clientId }));
      } catch (e) {
        if (e.kind === 'login') {
          localStorage.removeItem(KEY.refresh);
          if (e.oauthError === 'invalid_client') localStorage.removeItem(KEY.client);
        }
        throw e;
      }
    }).finally(() => {
      auth.refreshing = null;
    });
  }
  return auth.refreshing;
}

/** JSON-RPC を 1 つ（またはバッチを 1 つ）送る。401 なら refresh を 1 回だけ試してやり直す。 */
async function post(payload, { timeout = TIMEOUT_MS.normal, signal } = {}) {
  for (let attempt = 0; ; attempt += 1) {
    if (!auth.access || Date.now() >= auth.expiresAt - 30000) await refresh(auth.gen);
    const gen = auth.gen;
    const { status, body } = await request(MCP_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${auth.access}`,
      },
      body: JSON.stringify(payload),
    }, timeout, signal);
    if (status === 401) {
      if (attempt === 0) {
        await refresh(gen);
        continue;
      }
      localStorage.removeItem(KEY.refresh);
      throw new AppError('トークンを受け付けてもらえなかった。ログインし直す', 'login');
    }
    if (status !== 200 || body == null) throw httpError(status, body);
    return body;
  }
}

let rpcId = 0;

function toolError(result) {
  const text = result?.content?.find((c) => c.type === 'text')?.text ?? 'エラー';
  return new AppError(text.replace(/^Error: /, ''), 'tool');
}

async function callToolRaw(name, args, opts) {
  const body = await post({ jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: { name, arguments: args } }, opts);
  if (body.error) throw new AppError(`JSON-RPC エラー: ${body.error.message}`, 'rpc');
  if (body.result?.isError) throw toolError(body.result);
  return body.result;
}

async function tool(name, args, opts) {
  try {
    return (await callToolRaw(name, args, opts)).structuredContent ?? {};
  } catch (e) {
    if (e.kind === 'login') requireLogin(e.message);
    throw e;
  }
}

/** 同じ tool を引数違いでまとめて呼ぶ。結果は {value} か {error} の配列。 */
async function toolBatch(name, argsList, opts) {
  const base = rpcId;
  rpcId += argsList.length;
  const payload = argsList.map((a, i) => ({
    jsonrpc: '2.0', id: base + i + 1, method: 'tools/call', params: { name, arguments: a },
  }));
  let body;
  try {
    body = await post(payload, opts);
  } catch (e) {
    if (e.kind === 'login') requireLogin(e.message);
    throw e;
  }
  if (!Array.isArray(body)) throw new AppError(body?.error?.message ?? 'バッチの応答が不正', 'rpc');
  const byId = new Map(body.map((r) => [r.id, r]));
  return argsList.map((_, i) => {
    const r = byId.get(base + i + 1);
    if (!r) return { error: '応答が無い' };
    if (r.error) return { error: r.error.message };
    if (r.result?.isError) return { error: toolError(r.result).message };
    return { value: r.result?.structuredContent ?? {} };
  });
}

// 登録は、トークンを持たない古いものから消されうる。消えた client_id で /authorize へ行くと
// 400 の JSON で止まって戻ってこられないので、先に確かめる。/revoke は知らないトークンなら何もせず 200、
// 知らないクライアントなら 401 invalid_client を返す（RFC 7009）。
async function clientExists(clientId) {
  const { status } = await request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, token: 'probe' }),
  }, TIMEOUT_MS.normal);
  if (status === 200) return true;
  if (status === 401) return false;
  throw httpError(status, null);
}

async function ensureClient() {
  const saved = localStorage.getItem(KEY.client);
  if (saved && (await clientExists(saved))) return saved;
  const { status, body } = await request('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      client_name: 'relay Web チャット',
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      application_type: 'web',
    }),
  }, TIMEOUT_MS.normal);
  if (status !== 201 || typeof body?.client_id !== 'string') throw httpError(status, body);
  localStorage.setItem(KEY.client, body.client_id);
  return body.client_id;
}

async function login() {
  if (!crypto.subtle) {
    ui.login.status('error', 'この画面は HTTPS（またはローカルの http://127.0.0.1）で開く必要がある。');
    return;
  }
  ui.login.status('loading', 'クライアントを確認中…');
  try {
    const clientId = await ensureClient();
    const verifier = randomString(32);
    const state = randomString(24);
    const returnTo = location.pathname === CALLBACK_PATH ? '#/threads' : location.hash || '#/threads';
    sessionStorage.setItem(KEY.pkce, JSON.stringify({ state, verifier, clientId, returnTo }));
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      code_challenge: await s256(verifier),
      code_challenge_method: 'S256',
      state,
      resource: RESOURCE,
    });
    ui.login.status('loading', '認可画面へ移動中…');
    location.assign(`/authorize?${query}`);
  } catch (e) {
    ui.login.status('error', `ログインを始められなかった: ${e.message}`);
  }
}

/** /relay/callback に戻ってきたとき。成功なら true、失敗はログイン画面に理由を出す。 */
async function handleCallback() {
  const q = new URLSearchParams(location.search);
  const saved = parseJson(sessionStorage.getItem(KEY.pkce) ?? 'null');
  sessionStorage.removeItem(KEY.pkce);
  // 認可コードを履歴とアドレスバーに残さない
  history.replaceState(null, '', `/relay/${saved?.returnTo ?? '#/threads'}`);
  if (!saved || q.get('state') !== saved.state) {
    throw new AppError('認可の応答を確かめられなかった（state が一致しない）。もう一度ログインする。', 'login');
  }
  if (q.get('error')) {
    throw new AppError(`認可されなかった: ${q.get('error_description') || q.get('error')}`, 'login');
  }
  const code = q.get('code');
  if (!code) throw new AppError('認可コードが無い。もう一度ログインする。', 'login');
  const t = await tokenRequest({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: saved.clientId,
    code_verifier: saved.verifier,
  });
  localStorage.setItem(KEY.client, saved.clientId);
  storeTokens(t);
}

async function logout() {
  const rt = localStorage.getItem(KEY.refresh);
  const clientId = localStorage.getItem(KEY.client);
  localStorage.removeItem(KEY.refresh);
  localStorage.removeItem(KEY.participants);
  channel?.postMessage({ type: 'logout' });
  requireLogin('ログアウトした。');
  if (rt && clientId) {
    try {
      await request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: clientId, token: rt }),
      }, TIMEOUT_MS.normal);
    } catch {
      // 失効できなくても手元からは消してある
    }
  }
}

// ---------------------------------------------------------------------------
// 状態

const idle = () => ({ phase: 'idle', error: null, at: 0 });

const S = {
  signedIn: false,
  route: { list: 'threads', agent: null, query: null, thread: null, focus: null, compose: null },
  listHash: '#/threads',
  agents: { st: idle(), items: [], includeSeen: false },
  threads: { st: idle(), items: [] },
  // for: 結果がどの検索語のものか
  search: { st: idle(), for: '', items: [], hasMore: false },
  // thread id -> { sig, names }。参加者はメッセージの from/to から求める（サーバに台帳は無い）
  parts: { st: idle(), map: readParticipants(), done: 0, total: 0 },
  // fresh: 開いてから届いた・開いたときに未読だったメッセージ（既読にしたあとも印を残す）
  // focus: 読み込めたらそこまでスクロールするメッセージ id（検索結果から開いたとき）
  conv: { st: idle(), id: null, thread: null, messages: [], fresh: new Set(), focus: null },
  // thread id（新規会話は "new"）-> 送信中・失敗したメッセージ
  pending: new Map(),
  drafts: new Map(),
  toChoice: new Map(),
  poll: { phase: 'stopped', error: null },
};

function readParticipants() {
  const raw = parseJson(localStorage.getItem(KEY.participants) ?? 'null');
  const map = new Map();
  if (raw && typeof raw === 'object') {
    for (const [id, v] of Object.entries(raw)) {
      if (typeof v?.sig === 'string' && Array.isArray(v.names)) map.set(id, v);
    }
  }
  return map;
}

function saveParticipants() {
  const keep = new Set(S.threads.items.map((t) => t.id));
  const out = {};
  for (const [id, v] of S.parts.map) if (keep.has(id)) out[id] = v;
  try {
    localStorage.setItem(KEY.participants, JSON.stringify(out));
  } catch {
    // 入らなければメモリだけで使う
  }
}

const threadSig = (t) => `${t.message_count}|${t.updated_at}`;

function participantsOf(messages) {
  const names = new Set();
  for (const m of messages) {
    names.add(m.from);
    names.add(m.to);
  }
  return [...names].sort();
}

function rememberParticipants(thread, messages) {
  S.parts.map.set(thread.id, {
    sig: `${messages.length}|${thread.updated_at}`,
    names: participantsOf(messages),
  });
}

/** 取得を 1 本ずつに保つ。新しい取得を始めたら古いものは中断し、結果も捨てる。 */
function loader(slot, fetcher, commit, render) {
  let ctrl = null;
  let seq = 0;
  const run = async () => {
    ctrl?.abort();
    ctrl = new AbortController();
    const my = ++seq;
    slot.st = { ...slot.st, phase: 'loading', error: null };
    render();
    try {
      const data = await fetcher(ctrl.signal);
      if (my !== seq) return;
      commit(data);
      slot.st = { phase: 'ok', error: null, at: Date.now() };
    } catch (e) {
      if (my !== seq || e.kind === 'aborted') return;
      slot.st = { ...slot.st, phase: 'error', error: e.message };
    }
    render();
  };
  /** 走っている取得を止め、結果も捨てる。 */
  run.cancel = () => {
    ctrl?.abort();
    seq += 1;
  };
  return run;
}

const loadAgents = loader(
  S.agents,
  (signal) => tool('list_agents', { include_seen: S.agents.includeSeen }, { signal }),
  (r) => {
    S.agents.items = Array.isArray(r.agents) ? r.agents : [];
  },
  () => {
    renderList();
    updateComposer();
  },
);

const loadThreads = loader(
  S.threads,
  (signal) => tool('list_threads', { agent: ME, limit: THREAD_LIMIT }, { signal }),
  (r) => {
    S.threads.items = Array.isArray(r.threads) ? r.threads : [];
    queueMicrotask(loadParticipants);
  },
  () => {
    renderList();
    renderTitle();
  },
);

const loadParticipants = loader(
  S.parts,
  async (signal) => {
    const need = S.threads.items.filter((t) => S.parts.map.get(t.id)?.sig !== threadSig(t));
    S.parts.done = 0;
    S.parts.total = need.length;
    for (let i = 0; i < need.length; i += PARTICIPANT_BATCH) {
      const chunk = need.slice(i, i + PARTICIPANT_BATCH);
      const results = await toolBatch('get_thread', chunk.map((t) => ({ thread_id: t.id })), { signal });
      const failed = results.find((r) => r.error && !/not found/.test(r.error));
      if (failed) throw new AppError(failed.error, 'tool');
      results.forEach((r, j) => {
        if (r.value?.thread) rememberParticipants(r.value.thread, r.value.messages ?? []);
        // 一覧と取得の間に消えたスレッドは、次の一覧から落ちる
        else S.parts.map.set(chunk[j].id, { sig: threadSig(chunk[j]), names: [] });
      });
      S.parts.done += chunk.length;
      renderList();
    }
  },
  () => saveParticipants(),
  () => renderList(),
);

const loadConv = loader(
  S.conv,
  (signal) => tool('get_thread', { thread_id: S.conv.id }, { signal }),
  (r) => {
    S.conv.thread = r.thread;
    S.conv.messages = r.messages ?? [];
    rememberParticipants(r.thread, S.conv.messages);
    dropDelivered(S.conv.id);
    if (S.conv.focus && !S.conv.messages.some((m) => m.id === S.conv.focus)) {
      S.conv.focus = null;
      notify('検索で選んだメッセージがこのスレッドに無かった（送信から 7 日で消える）。');
    }
    const unread = S.conv.messages.filter((m) => m.to === ME && !m.read).map((m) => m.id);
    for (const id of unread) S.conv.fresh.add(id);
    if (unread.length) markRead(S.conv.id, { thread_id: S.conv.id });
  },
  () => {
    renderConv();
    renderList();
  },
);

const loadSearch = loader(
  S.search,
  (signal) => tool('search_messages', { query: S.search.for, limit: SEARCH_LIMIT }, { signal }),
  (r) => {
    S.search.items = Array.isArray(r.results) ? r.results : [];
    S.search.hasMore = Boolean(r.has_more);
  },
  () => renderList(),
);

/** 検索語が変わったときだけ検索し直す（スレッドから戻ったときは結果をそのまま見せる）。 */
function runSearch() {
  const q = S.route.query ?? '';
  if (q === S.search.for && S.search.st.phase !== 'idle') return;
  loadSearch.cancel();
  S.search.for = q;
  S.search.items = [];
  S.search.hasMore = false;
  S.search.st = idle();
  if (q.trim()) loadSearch();
}

function submitSearch() {
  const input = ui.search.input;
  const q = input.value;
  if (!q.trim()) {
    input.focus();
    return;
  }
  // 同じ語でもう一度押されたら取り直す
  if (q === S.search.for) loadSearch();
  const hash = searchHash(q);
  if (location.hash !== hash) location.hash = hash;
}

async function markRead(threadId, selector) {
  try {
    await tool('mark_read', { agent: ME, ...selector });
    const ids = new Set(selector.message_ids ?? []);
    for (const m of S.conv.messages) {
      if (m.to === ME && (selector.thread_id || ids.has(m.id))) m.read = true;
    }
    const t = S.threads.items.find((x) => x.id === threadId);
    if (t) {
      t.unread_count = selector.thread_id ? 0 : Math.max(0, (t.unread_count ?? 0) - ids.size);
      renderList();
      renderTitle();
    }
  } catch (e) {
    if (e.kind !== 'login') notify(`既読にできなかった: ${e.message}`);
  }
}

let threadsReloadTimer = null;
function scheduleThreadsReload() {
  clearTimeout(threadsReloadTimer);
  threadsReloadTimer = setTimeout(loadThreads, 400);
}

async function ensureUserRegistered() {
  try {
    const { agents } = await tool('list_agents', {});
    // 既に登録があれば触らない（register_agent は説明ごと置き換え、持ち主の違うクライアントからは断られる）
    if (Array.isArray(agents) && agents.some((a) => a.name === ME)) return;
    await tool('register_agent', { agent: ME, description: USER_DESCRIPTION });
    loadAgents();
  } catch (e) {
    if (e.kind !== 'login') notify(`「${ME}」を relay に登録できなかった: ${e.message}`, ensureUserRegistered);
  }
}

// ---------------------------------------------------------------------------
// 受信（会話を開いている間も一覧の間も、表に出ている間だけ long-poll を続ける）

const poller = {
  token: null,
  cursor: null,
  ctrl: null,
  wake: null,

  start() {
    if (this.token || document.hidden || !S.signedIn) return;
    const token = {};
    this.token = token;
    this.loop(token);
  },

  stop(phase) {
    this.token = null;
    this.ctrl?.abort();
    this.wake?.();
    setPoll(phase, null);
  },

  retryNow() {
    this.wake?.();
  },

  sleep(ms) {
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this.wake = null;
        resolve();
      };
      const timer = setTimeout(done, ms);
      this.wake = done;
    });
  },

  async loop(token) {
    let backoff = 0;
    let more = false;
    while (this.token === token) {
      if (!S.signedIn) break;
      this.ctrl = new AbortController();
      const { signal } = this.ctrl;
      try {
        if (this.cursor == null) {
          setPoll('starting', null);
          this.cursor = await initialCursor(signal);
        }
        setPoll('waiting', null);
        const r = await tool('check_messages', {
          agent: ME,
          unread_only: false,
          since_cursor: this.cursor,
          limit: 100,
          wait_seconds: more ? 0 : POLL_WAIT_SECONDS,
        }, { timeout: TIMEOUT_MS.poll, signal });
        if (this.token !== token) break;
        if (r.next_cursor != null) this.cursor = String(r.next_cursor);
        more = Boolean(r.has_more);
        backoff = 0;
        if (Array.isArray(r.messages) && r.messages.length) onIncoming(r.messages);
      } catch (e) {
        if (this.token !== token || e.kind === 'aborted') break;
        if (e.kind === 'login') break;
        backoff = Math.min(60, backoff ? backoff * 2 : 3);
        setPoll('error', `${e.message}（${backoff} 秒後に再試行）`);
        await this.sleep(backoff * 1000);
      }
    }
    if (this.token === token) this.token = null;
  },
};

/** 部屋で一番新しいメッセージの id。これより後に来た自分宛てだけを受け取る。 */
async function initialCursor(signal) {
  const { threads } = await tool('list_threads', { limit: 1 }, { signal });
  if (!threads?.length) return '0';
  const { messages } = await tool('get_thread', { thread_id: threads[0].id }, { signal });
  return String(maxId(messages ?? []));
}

function onIncoming(messages) {
  const open = S.route.thread;
  const here = messages.filter((m) => m.thread_id === open);
  if (here.length && S.conv.st.phase === 'loading') {
    // 取得中の結果には入っていないかもしれないので取り直す
    loadConv();
  } else if (here.length && S.conv.id === open && S.conv.thread) {
    const known = new Set(S.conv.messages.map((m) => m.id));
    for (const m of here) {
      if (known.has(m.id)) continue;
      S.conv.messages.push(m);
      S.conv.fresh.add(m.id);
    }
    S.conv.messages.sort((a, b) => idNum(a.id) - idNum(b.id));
    rememberParticipants(S.conv.thread, S.conv.messages);
    renderConv();
    const unread = here.filter((m) => !m.read).map((m) => m.id);
    if (unread.length) markRead(open, { message_ids: unread });
  }
  scheduleThreadsReload();
}

function setPoll(phase, error) {
  S.poll = { phase, error };
  renderConn();
}

// ---------------------------------------------------------------------------
// 送信（楽観表示。応答で確定し、失敗なら再送できるように残す）

function composerKey() {
  if (S.route.thread) return S.route.thread;
  if (S.route.compose) return 'new';
  return null;
}

function pendingOf(key) {
  if (!S.pending.has(key)) S.pending.set(key, []);
  return S.pending.get(key);
}

function removePending(key, p) {
  const list = pendingOf(key).filter((x) => x !== p);
  if (list.length) S.pending.set(key, list);
  else S.pending.delete(key);
}

/** 届いたか分からないまま残っているものが、取り直したスレッドにあれば消す。 */
function dropDelivered(threadId) {
  const list = S.pending.get(threadId);
  if (!list) return;
  for (const p of list) {
    if (p.state === 'sending') continue;
    if (S.conv.messages.some((m) => m.from === ME && m.text === p.text && idNum(m.id) > p.afterId)) {
      removePending(threadId, p);
    }
  }
}

function submitComposer() {
  const key = composerKey();
  const c = ui.composer;
  if (!key || !canSend()) return;
  const p = {
    threadId: key === 'new' ? null : key,
    to: c.to.value,
    text: c.text.value,
    subject: key === 'new' ? c.subject.value.trim() : '',
    state: 'sending',
    error: null,
    afterId: key === 'new' ? 0 : maxId(S.conv.messages),
  };
  pendingOf(key).push(p);
  c.text.value = '';
  S.drafts.delete(key);
  if (key === 'new') c.subject.value = '';
  updateComposerState();
  autoGrow();
  renderConv({ toBottom: true });
  deliver(key, p);
}

async function deliver(key, p) {
  p.state = 'sending';
  p.error = null;
  renderConv({ toBottom: true });
  const args = { agent: ME, to: p.to, text: p.text };
  if (p.threadId) args.thread_id = p.threadId;
  else if (p.subject) args.subject = p.subject;
  try {
    const { message } = await tool('send_message', args, { timeout: TIMEOUT_MS.send });
    removePending(key, p);
    if (p.threadId) {
      if (S.conv.id === p.threadId && S.conv.thread && !S.conv.messages.some((m) => m.id === message.id)) {
        S.conv.messages.push(message);
        rememberParticipants(S.conv.thread, S.conv.messages);
      }
      renderConv({ toBottom: true });
    } else if (S.route.compose) {
      location.hash = threadHash(message.thread_id);
    } else {
      renderConv();
    }
    scheduleThreadsReload();
  } catch (e) {
    p.state = e.kind === 'timeout' ? 'unknown' : 'failed';
    p.error = e.message;
    renderConv();
  }
}

function restorePending(key, p) {
  removePending(key, p);
  const c = ui.composer;
  if (composerKey() === key && !c.text.value) {
    c.text.value = p.text;
    S.drafts.set(key, p.text);
    if (key === 'new' && p.subject && !c.subject.value) c.subject.value = p.subject;
    updateComposerState();
    autoGrow();
    c.text.focus();
  } else {
    S.drafts.set(key, p.text);
  }
  renderConv();
}

function canSend() {
  const c = ui.composer;
  const text = c.text.value;
  return Boolean(c.to.value) && text.trim().length > 0 && text.length <= MAX_TEXT;
}

// ---------------------------------------------------------------------------
// 添付（中身は押されたときに取り、ダウンロードさせるだけ。表示はしない）

async function downloadAttachment(att, button, note) {
  button.disabled = true;
  button.textContent = '取得中…';
  note.textContent = '';
  try {
    const result = await callToolRaw('get_attachment', { attachment_id: att.id }, { timeout: TIMEOUT_MS.attachment });
    const image = result.content?.find((c) => c.type === 'image');
    const b64 = image?.data ?? parseJson(result.content?.find((c) => c.type === 'text')?.text ?? '')?.content_base64;
    if (typeof b64 !== 'string') throw new AppError('添付の中身が無い', 'tool');
    const raw = atob(b64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
    // 種類は送り手の申告なので使わない（ブラウザに開かせず、必ず保存させる）
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const a = h('a', { href: url, download: att.filename || 'attachment' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    button.textContent = 'ダウンロード';
  } catch (e) {
    if (e.kind === 'login') requireLogin(e.message);
    button.textContent = '再試行';
    note.textContent = `失敗: ${e.message}`;
  } finally {
    button.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// 画面

const ui = {};

function buildShell() {
  ui.conn = h('span', { class: 'conn', role: 'status' });
  ui.tabAgents = h('a', { href: '#/agents' }, 'エージェント');
  ui.tabThreads = h('a', { href: '#/threads' }, 'スレッド');
  ui.tabSearch = h('a', { href: '#/search' }, '検索');
  ui.notices = h('div', { class: 'notices' });
  ui.search = buildSearch();
  ui.listBody = h('div', { class: 'list-body' });
  // 検索欄は描き直さない（入力中にフォーカスを失わないように）
  ui.listPane = h('section', { class: 'pane list-pane', 'aria-label': '一覧' }, ui.search.form, ui.listBody);
  ui.convHead = h('div', { class: 'pane-head' });
  ui.convSub = h('div');
  ui.convStatus = h('div');
  ui.msgs = h('div', { class: 'msgs' });
  ui.composer = buildComposer();
  ui.convPane = h('section', { class: 'pane conv-pane', 'aria-label': '会話' },
    ui.convHead, ui.convSub, ui.convStatus, ui.msgs, ui.composer.form);
  ui.layout = h('main', { class: 'layout', 'data-pane': 'list' }, ui.listPane, ui.convPane);
  ui.login = buildLogin();
  document.getElementById('app').replaceChildren(
    h('header', { class: 'top' },
      h('h1', {}, 'relay'),
      h('nav', { class: 'tabs' }, ui.tabAgents, ui.tabThreads, ui.tabSearch),
      ui.conn,
      h('button', { type: 'button', class: 'link', onclick: logout }, 'ログアウト')),
    ui.notices,
    ui.layout,
    ui.login.el,
  );
}

function buildLogin() {
  const reason = h('p', { class: 'reason' });
  const state = h('p', { class: 'status', role: 'status' });
  const button = h('button', { type: 'button', class: 'primary', onclick: login }, 'GitHub でログイン');
  const el = h('div', { class: 'login', hidden: true },
    h('div', { class: 'card' },
      h('h2', {}, 'relay チャット'),
      reason,
      h('p', {}, `relay に agent「${ME}」として参加し、エージェントと会話する。`),
      h('p', { class: 'note' }, '初回は接続の確認画面が出る。このサーバへの接続を許可してから GitHub でログインする。'),
      state,
      button));
  return {
    el,
    show(why) {
      reason.textContent = why ?? '';
      reason.hidden = !why;
      state.replaceChildren();
      state.className = 'status';
      button.disabled = false;
      el.hidden = false;
    },
    hide() {
      el.hidden = true;
    },
    status(phase, text) {
      state.className = `status ${phase}`;
      state.replaceChildren(h('span', {}, text));
      button.disabled = phase === 'loading';
    },
  };
}

function buildSearch() {
  const input = h('input', {
    type: 'search',
    maxlength: MAX_QUERY,
    placeholder: '本文を検索',
    'aria-label': '検索語',
    enterkeyhint: 'search',
    autocomplete: 'off',
  });
  const button = h('button', { type: 'submit', class: 'primary' }, '検索');
  const form = h('form', { class: 'pane-head search', role: 'search', hidden: true }, input, button);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    submitSearch();
  });
  return { form, input };
}

function buildComposer() {
  const c = {};
  c.to = h('select', { 'aria-label': '宛先' });
  c.subject = h('input', { type: 'text', maxlength: MAX_SUBJECT, placeholder: '件名（省略可）', 'aria-label': '件名' });
  c.subjectRow = h('div', { class: 'row' }, c.subject);
  c.text = h('textarea', { rows: 2, placeholder: 'メッセージ（Ctrl+Enter で送信）', 'aria-label': 'メッセージ' });
  c.count = h('span', { class: 'count', 'aria-live': 'polite' });
  c.send = h('button', { type: 'submit', class: 'primary' }, '送信');
  c.form = h('form', { class: 'composer', hidden: true },
    h('div', { class: 'row' }, h('span', { class: 'label' }, '宛先'), c.to),
    c.subjectRow,
    c.text,
    h('div', { class: 'row' }, c.count, c.send));
  c.form.addEventListener('submit', (e) => {
    e.preventDefault();
    submitComposer();
  });
  c.text.addEventListener('input', () => {
    const key = composerKey();
    if (key) S.drafts.set(key, c.text.value);
    updateComposerState();
    autoGrow();
  });
  c.text.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      submitComposer();
    }
  });
  c.subject.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      c.text.focus();
    }
  });
  c.to.addEventListener('change', () => {
    const key = composerKey();
    if (key) S.toChoice.set(key, c.to.value);
    updateComposerState();
  });
  c.key = null;
  return c;
}

function autoGrow() {
  const t = ui.composer.text;
  t.style.height = 'auto';
  // 隠れている間は高さが測れない
  if (t.scrollHeight) t.style.height = `${t.scrollHeight + 2}px`;
}

function notify(text, retry) {
  const el = h('div', { class: 'notice', role: 'alert' }, h('span', {}, text));
  if (retry) {
    el.append(h('button', { type: 'button', class: 'small', onclick: () => { el.remove(); retry(); } }, '再試行'));
  }
  el.append(h('button', { type: 'button', class: 'small', 'aria-label': '閉じる', onclick: () => el.remove() }, '×'));
  ui.notices.append(el);
  while (ui.notices.children.length > 3) ui.notices.firstElementChild.remove();
}

/** 取得状態の行。データがあるまま取り直しているときは「更新中」。 */
function statusLine(st, label, retry, hasData) {
  if (st.phase === 'loading') {
    return h('p', { class: 'status loading', role: 'status' }, h('span', {}, hasData ? `${label}を更新中…` : `${label}を読み込み中…`));
  }
  if (st.phase === 'error') {
    return h('p', { class: 'status error', role: 'alert' },
      h('span', {}, `${label}を取得できなかった: ${st.error}`),
      h('button', { type: 'button', class: 'small', onclick: retry }, '再試行'));
  }
  if (st.phase === 'ok') {
    return h('p', { class: 'status' },
      h('span', {}, `${label}: ${clockFormat.format(st.at)} に取得`),
      h('button', { type: 'button', class: 'small', onclick: retry }, '更新'));
  }
  return null;
}

function renderConn() {
  if (!ui.conn) return;
  const { phase, error } = S.poll;
  const text = {
    starting: '受信を準備中…',
    waiting: '受信待機中',
    paused: '背面のため受信を停止中',
    stopped: '受信停止',
    error: `受信エラー: ${error}`,
  }[phase] ?? '';
  ui.conn.className = `conn ${phase}`;
  ui.conn.replaceChildren(h('span', {}, text));
  ui.conn.title = text;
  if (phase === 'error') {
    ui.conn.append(h('button', { type: 'button', class: 'small', onclick: () => poller.retryNow() }, '今すぐ'));
  }
}

function renderTitle() {
  const unread = S.threads.items.reduce((n, t) => n + (t.unread_count ?? 0), 0);
  document.title = unread ? `(${unread}) relay チャット` : 'relay チャット';
}

function renderList() {
  if (!ui.listPane) return;
  const { list } = S.route;
  const tabs = { agents: ui.tabAgents, threads: ui.tabThreads, search: ui.tabSearch };
  for (const [name, tab] of Object.entries(tabs)) {
    if (name === list) tab.setAttribute('aria-current', 'page');
    else tab.removeAttribute('aria-current');
  }
  ui.tabSearch.setAttribute('href', searchHash(S.search.for));
  ui.search.form.hidden = list !== 'search';
  const view = { agents: agentsView, search: searchView }[list]?.() ?? threadsView();
  ui.listBody.replaceChildren(...view.filter(Boolean));
}

function agentsView() {
  const { st, items, includeSeen } = S.agents;
  const toggle = h('input', { type: 'checkbox', checked: includeSeen });
  toggle.addEventListener('change', () => {
    S.agents.includeSeen = toggle.checked;
    loadAgents();
  });
  const head = h('div', { class: 'pane-head' },
    h('h2', {}, 'エージェント'),
    h('label', { class: 'meta' }, toggle, ' 未登録の相手も'));
  const out = [head, statusLine(st, 'エージェント一覧', loadAgents, items.length > 0)];
  if (st.phase === 'ok' && !items.length) {
    out.push(h('p', { class: 'empty' }, '登録されているエージェントは無い。'));
  }
  out.push(h('ul', { class: 'list' }, items.map((a) => {
    const mine = a.name === ME;
    return h('li', {},
      h('a', { class: 'item', href: threadsHash(a.name) },
        h('div', { class: 'row' },
          h('span', { class: 'name' }, a.name),
          mine ? h('span', { class: 'badge' }, '自分') : null,
          h('span', { class: 'badge' }, a.webhook ? 'webhook あり' : 'webhook なし')),
        h('div', { class: 'desc' }, a.description ?? '（説明なし）')),
      mine ? null : h('div', { class: 'actions' },
        h('a', { href: threadsHash(a.name) }, '参加スレッド'),
        h('a', { href: newHash(a.name) }, '新規会話')));
  })));
  return out;
}

function threadsView() {
  const { st, items } = S.threads;
  const agent = S.route.agent;
  const head = h('div', { class: 'pane-head' },
    h('h2', {}, 'スレッド'),
    h('a', { class: 'button', href: newHash(agent) }, '新規会話'));
  const out = [head];
  if (agent) {
    out.push(h('div', { class: 'pane-sub' },
      h('span', { class: 'filter' },
        h('span', {}, `${agent} が参加`),
        h('a', { href: '#/threads', 'aria-label': '絞り込みを解除' }, '×'))));
  }
  out.push(statusLine(st, 'スレッド一覧', loadThreads, items.length > 0));
  const parts = S.parts;
  if (parts.st.phase === 'loading' && parts.done < parts.total) {
    out.push(h('p', { class: 'status loading', role: 'status' },
      h('span', {}, `参加者を確認中 ${parts.done}/${parts.total}`)));
  } else if (parts.st.phase === 'error') {
    out.push(statusLine(parts.st, '参加者', loadParticipants, false));
  }
  let shown = items;
  if (agent) shown = items.filter((t) => S.parts.map.get(t.id)?.names.includes(agent));
  if (st.phase === 'ok' && !shown.length) {
    const waiting = agent && parts.st.phase === 'loading';
    out.push(h('p', { class: 'empty' },
      waiting ? '参加者を確認している。' : agent ? `${agent} が参加するスレッドは無い。` : 'スレッドは無い。'));
  }
  out.push(h('ul', { class: 'list' }, shown.map((t) => {
    const names = S.parts.map.get(t.id)?.names;
    const unread = t.unread_count ?? 0;
    return h('li', {},
      h('a', { class: 'item', href: threadHash(t.id), 'aria-current': S.route.thread === t.id ? 'true' : null },
        h('div', { class: 'row' },
          h('span', { class: 'title' }, t.subject || '（件名なし）'),
          unread ? h('span', { class: 'badge unread', title: '未読' }, unread) : null),
        h('div', { class: 'meta' },
          `${t.message_count ?? 0} 件 · ${formatDate(t.updated_at)}`,
          names?.length ? ` · ${names.join(', ')}` : '')));
  })));
  if (items.length >= THREAD_LIMIT) {
    out.push(h('p', { class: 'more' }, `新しい順に ${THREAD_LIMIT} 件まで表示している。`));
  }
  return out;
}

function searchView() {
  const { st, items, hasMore } = S.search;
  const q = S.search.for;
  if (!q.trim()) {
    return [h('p', { class: 'empty' },
      `本文の一部を入れて検索する。この部屋のすべてのスレッドから、新しい順に ${SEARCH_LIMIT} 件まで出す。`)];
  }
  const out = [statusLine(st, '検索結果', loadSearch, items.length > 0)];
  if (st.phase === 'ok') {
    out.push(h('div', { class: 'pane-sub' },
      `「${q}」を含むメッセージ: ${items.length}${hasMore ? ' 件以上' : ' 件'}`));
    if (!items.length) out.push(h('p', { class: 'empty' }, '見つからなかった。メッセージは送信から 7 日で消える。'));
  }
  out.push(h('ul', { class: 'list' }, items.map((r) => {
    const ex = r.excerpt ?? {};
    const current = S.route.thread === r.thread_id && S.route.focus === r.id;
    return h('li', {},
      h('a', { class: 'item', href: threadHash(r.thread_id, r.id), 'aria-current': current ? 'true' : null },
        h('div', { class: 'row' }, h('span', { class: 'title' }, r.subject || '（件名なし）')),
        h('div', { class: 'meta' }, `${r.from} → ${r.to} · ${formatDate(r.created_at)}`),
        h('div', { class: 'excerpt' },
          tail(ex.before, EXCERPT_BEFORE),
          h('mark', {}, ex.match ?? ''),
          ex.after ?? '')));
  })));
  if (hasMore) {
    out.push(h('p', { class: 'more' }, `新しい順に ${SEARCH_LIMIT} 件まで表示している。語を足して絞り込む。`));
  }
  return out;
}

function renderConv(opts = {}) {
  if (!ui.convPane) return;
  const key = composerKey();
  const back = h('a', { class: 'back', href: S.listHash }, '‹ 一覧');
  if (S.route.compose) {
    ui.convHead.replaceChildren(back, h('h2', {}, '新規会話'));
    ui.convSub.replaceChildren();
    ui.convStatus.replaceChildren();
    renderMessages([], pendingOf('new'), 'new', opts, 'まだメッセージは無い。宛先を選んで送ると新しいスレッドができる。');
  } else if (S.route.thread) {
    const { thread, messages, st } = S.conv;
    const loaded = Boolean(thread) && S.conv.id === S.route.thread;
    ui.convHead.replaceChildren(back, h('h2', {}, loaded ? thread.subject || '（件名なし）' : 'スレッド'));
    const names = loaded ? participantsOf(messages) : [];
    ui.convSub.replaceChildren(...(names.length
      ? [h('div', { class: 'pane-sub' }, `参加: ${names.join(', ')} · ${messages.length} 件`)]
      : []));
    ui.convStatus.replaceChildren(...[statusLine(st, 'スレッド', loadConv, loaded)].filter(Boolean));
    renderMessages(loaded ? messages : [], S.pending.get(key) ?? [], key, opts,
      loaded ? 'メッセージは無い。' : '');
  } else {
    ui.convHead.replaceChildren(h('h2', {}, '会話'));
    ui.convSub.replaceChildren();
    ui.convStatus.replaceChildren();
    ui.msgs.replaceChildren(h('p', { class: 'placeholder' }, 'スレッドを選ぶか、新規会話を始める。'));
  }
  updateComposer();
}

function renderMessages(messages, pending, key, opts, emptyText) {
  const box = ui.msgs;
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const nodes = messages.map(messageView);
  for (const p of pending) nodes.push(pendingView(key, p));
  if (!nodes.length && emptyText) nodes.push(h('p', { class: 'placeholder' }, emptyText));
  box.replaceChildren(...nodes);
  const focus = S.conv.focus ? messages.findIndex((m) => m.id === S.conv.focus) : -1;
  if (focus >= 0) {
    S.conv.focus = null;
    nodes[focus].scrollIntoView({ block: 'center' });
  } else if (opts.toBottom || nearBottom || opts.reset) {
    box.scrollTop = box.scrollHeight;
  }
}

function messageView(m) {
  const mine = m.from === ME;
  const hit = S.route.focus === m.id;
  return h('article', { class: `msg${mine ? ' mine' : ''}${hit ? ' hit' : ''}`, 'data-id': m.id },
    h('div', { class: 'meta' },
      mine ? null : h('span', { class: 'from' }, m.from),
      m.to !== ME ? h('span', {}, `→ ${m.to}`) : null,
      h('time', { datetime: m.created_at }, formatDate(m.created_at)),
      S.conv.fresh.has(m.id) ? h('span', { class: 'new' }, '新着') : null),
    m.text ? h('div', { class: 'text' }, m.text) : null,
    m.attachments?.length ? h('ul', { class: 'atts' }, m.attachments.map(attachmentView)) : null);
}

function attachmentView(att) {
  const note = h('span', { class: 'size' });
  const button = h('button', { type: 'button', class: 'small' }, 'ダウンロード');
  button.addEventListener('click', () => downloadAttachment(att, button, note));
  return h('li', {},
    h('span', { class: 'file' }, `📎 ${att.filename}`),
    h('span', { class: 'size' }, formatSize(att.size ?? 0)),
    button,
    note);
}

function pendingView(key, p) {
  const failed = p.state !== 'sending';
  const state = {
    sending: h('div', { class: 'state' }, '送信中…'),
    failed: h('div', { class: 'state error' }, `送信できなかった: ${p.error}`),
    unknown: h('div', { class: 'state error' },
      `届いたか分からない: ${p.error}。届いていれば、スレッドを取り直したときに消える（再送すると重複しうる）。`),
  }[p.state];
  if (failed) {
    state.append(
      h('button', { type: 'button', class: 'small', onclick: () => deliver(key, p) }, '再送'),
      h('button', { type: 'button', class: 'small', onclick: () => restorePending(key, p) }, '入力欄に戻す'));
  }
  return h('article', { class: `msg mine pending${failed ? ' failed' : ''}` },
    h('div', { class: 'meta' }, h('span', {}, `→ ${p.to}`), p.subject ? h('span', {}, `件名: ${p.subject}`) : null),
    h('div', { class: 'text' }, p.text),
    state);
}

/** 宛先の既定: 最後に自分以外が話した相手。無ければ自分の最後の宛先、スレッドを始めた人。 */
function defaultTo(messages, thread) {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const m = messages[i];
    if (m.from !== ME) return m.from;
    if (m.to !== ME) return m.to;
  }
  return thread?.started_by !== ME ? thread?.started_by ?? '' : '';
}

function updateComposer() {
  const c = ui.composer;
  if (!c) return;
  const key = composerKey();
  const ready = key === 'new' || (key && S.conv.id === key && S.conv.thread);
  c.form.hidden = !ready;
  if (!ready) return;
  if (c.key !== key) {
    c.key = key;
    c.text.value = S.drafts.get(key) ?? '';
    autoGrow();
  }
  c.subjectRow.hidden = key !== 'new';

  const agents = S.agents.items.map((a) => a.name).filter((n) => n !== ME);
  let inThread = [];
  let wanted = S.toChoice.get(key);
  if (key === 'new') {
    wanted = wanted ?? S.route.compose?.to ?? '';
  } else {
    inThread = participantsOf(S.conv.messages).filter((n) => n !== ME);
    wanted = wanted ?? defaultTo(S.conv.messages, S.conv.thread);
  }
  const others = agents.filter((n) => !inThread.includes(n));
  if (wanted && !inThread.includes(wanted) && !others.includes(wanted)) others.unshift(wanted);
  // 選択肢が変わらなければ作り直さない（開いている選択肢を閉じない）
  const sig = JSON.stringify([key, wanted, inThread, others]);
  if (c.toSig !== sig) {
    c.toSig = sig;
    const option = (n) => h('option', { value: n, selected: n === wanted }, n);
    const groups = [];
    if (!wanted) groups.push(h('option', { value: '', selected: true }, '（宛先を選ぶ）'));
    if (inThread.length) groups.push(h('optgroup', { label: 'このスレッド' }, inThread.map(option)));
    if (others.length) {
      groups.push(h('optgroup', { label: inThread.length ? 'ほかのエージェント' : 'エージェント' }, others.map(option)));
    }
    c.to.replaceChildren(...groups);
    c.to.value = wanted;
  }
  updateComposerState();
}

function updateComposerState() {
  const c = ui.composer;
  const n = c.text.value.length;
  c.count.textContent = `${n.toLocaleString('ja-JP')} / ${MAX_TEXT.toLocaleString('ja-JP')} 文字`;
  c.count.classList.toggle('over', n > MAX_TEXT);
  c.send.disabled = !canSend();
}

// ---------------------------------------------------------------------------
// 画面の切り替え（#/agents, #/threads?agent=…, #/search?q=…, #/t/<thread_id>?m=<message_id>, #/new?to=…）

function parseRoute() {
  const raw = location.hash.replace(/^#/, '');
  const at = raw.indexOf('?');
  const path = at < 0 ? raw : raw.slice(0, at);
  const q = new URLSearchParams(at < 0 ? '' : raw.slice(at + 1));
  if (path === '/agents') return { list: 'agents' };
  if (path === '/threads') return { list: 'threads', agent: q.get('agent') || null };
  if (path === '/search') return { list: 'search', query: q.get('q') ?? '' };
  if (path.startsWith('/t/') && path.length > 3) {
    try {
      return { thread: decodeURIComponent(path.slice(3)), focus: q.get('m') || null };
    } catch {
      return null;
    }
  }
  if (path === '/new') return { compose: { to: q.get('to') || '' } };
  return null;
}

function route() {
  if (!S.signedIn) return;
  let r = parseRoute();
  if (!r) {
    history.replaceState(null, '', '#/threads');
    r = parseRoute();
  }
  const prevThread = S.route.thread;
  const prevFocus = S.route.focus;
  const prevCompose = S.route.compose;
  if (r.list) {
    S.route = { list: r.list, agent: r.agent ?? null, query: r.query ?? null, thread: null, focus: null, compose: null };
    S.listHash = location.hash;
    if (r.list === 'agents' && S.agents.st.phase === 'idle') loadAgents();
    if (r.list === 'threads' && S.threads.st.phase === 'idle') loadThreads();
    if (r.list === 'search') {
      ui.search.input.value = r.query;
      runSearch();
    }
  } else {
    S.route = { ...S.route, thread: r.thread ?? null, focus: r.focus ?? null, compose: r.compose ?? null };
  }
  ui.layout.dataset.pane = r.list ? 'list' : 'conv';
  if (S.route.thread && (S.route.thread !== prevThread || S.route.focus !== prevFocus)) {
    S.conv.focus = S.route.focus;
  }
  if (S.route.compose && prevCompose?.to !== S.route.compose.to) S.toChoice.delete('new');
  if (S.route.thread && S.route.thread !== prevThread) {
    if (S.conv.id !== S.route.thread) {
      S.conv.id = S.route.thread;
      S.conv.thread = null;
      S.conv.messages = [];
    }
    S.conv.fresh = new Set();
    renderConv({ reset: true });
    loadConv();
  } else {
    renderConv({ reset: S.route.compose && !prevCompose });
  }
  renderList();
  if (r.list === 'search' && !r.query) ui.search.input.focus();
}

// ---------------------------------------------------------------------------
// 起動・ログイン・表と裏

function requireLogin(reason) {
  S.signedIn = false;
  auth.access = null;
  poller.stop('stopped');
  poller.cursor = null;
  ui.login?.show(reason);
}

function startApp(fresh) {
  S.signedIn = true;
  ui.login.hide();
  loadAgents();
  loadThreads();
  route();
  poller.start();
  if (fresh) ensureUserRegistered();
}

let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    hiddenAt = Date.now();
    if (S.signedIn) poller.stop('paused');
    return;
  }
  if (!S.signedIn) return;
  poller.start();
  // 背面の間に他のエージェントどうしで進んだ分も拾う
  if (Date.now() - hiddenAt > 30000) {
    loadThreads();
    if (S.route.thread) loadConv();
  }
});

window.addEventListener('hashchange', route);

async function boot() {
  buildShell();
  renderConn();
  if (location.pathname === CALLBACK_PATH) {
    ui.layout.dataset.pane = 'list';
    ui.listBody.replaceChildren(h('p', { class: 'status loading', role: 'status' }, h('span', {}, 'ログイン処理中…')));
    try {
      await handleCallback();
    } catch (e) {
      requireLogin(e.message);
      return;
    }
    startApp(true);
    return;
  }
  if (!localStorage.getItem(KEY.refresh)) {
    requireLogin(null);
    return;
  }
  startApp(false);
}

boot();
