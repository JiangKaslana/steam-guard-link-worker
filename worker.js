const encoder = new TextEncoder();
const decoder = new TextDecoder();

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname.replace(/\/+$/, '') || '/';

      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204 });
      }

      if (pathname === '/api/login' && request.method === 'POST') {
        return handleLogin(request, env);
      }

      if (pathname === '/api/logout' && request.method === 'POST') {
        return handleLogout(request);
      }

      if (pathname === '/api/register-link' && request.method === 'POST') {
        return handleRegisterLink(request, env);
      }

      if (pathname === '/api/token' && request.method === 'POST') {
        return handleToken(request, env);
      }

      if (pathname === '/healthz' && request.method === 'GET') {
        return new Response('ok', {
          headers: { 'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8' },
        });
      }

      if (request.method === 'GET' && isAppPath(pathname)) {
        const authorized = await isAuthorized(request, env);
        if (!authorized) return htmlResponse(renderLoginPage(), env);
        return htmlResponse(renderApp(), env);
      }

      return json({ error: 'not_found' }, 404);
    } catch (err) {
      return json({ error: 'internal_error', message: err?.message || 'Unexpected server error.' }, 500);
    }
  },
};

// ========================
// 工具函数
// ========================

function isAppPath(pathname) {
  if (pathname === '/') return true;
  return /^\/[A-Za-z0-9_.-]+$/.test(pathname);
}

function readText(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : '';
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json; charset=utf-8',
      ...extraHeaders,
    },
  });
}

function htmlResponse(markup, env) {
  const nonce = randomNonce();
  const bg = backgroundImageValue(env);
  const ttl = String(linkTtlMinutes(env));
  const content = markup.replaceAll('__NONCE__', nonce).replaceAll('__BACKGROUND_IMAGE__', bg).replaceAll('__LINK_TTL_MINUTES__', ttl);

  return new Response(content, {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': [
        "default-src 'self'",
        "base-uri 'none'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self' data: https: http:",
        `style-src 'nonce-${nonce}'`,
        `script-src 'nonce-${nonce}'`,
      ].join('; '),
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function randomId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function constantTimeEqual(a, b) {
  const left = encoder.encode(String(a));
  const right = encoder.encode(String(b));
  let diff = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    diff |= (left[i] || 0) ^ (right[i] || 0);
  }
  return diff === 0;
}

function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64UrlDecode(str) {
  const clean = String(str || '').trim();
  if (!/^[A-Za-z0-9_-]*$/.test(clean)) throw new Error('Invalid base64url');
  const padded = clean.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(clean.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64ToBytes(value) {
  const clean = String(value || '').trim().replace(/\s+/g, '');
  const padded = clean.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(clean.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function linkTtlMinutes(env) {
  const raw = readText(env.LINK_TTL_MINUTES);
  if (!raw) return 30;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) return 30;
  return value;
}

function backgroundImageValue(env) {
  const url = readText(env.BACKGROUND_IMAGE_URL);
  return url ? `url("${cssString(url)}")` : 'none';
}

function cssString(value) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n|\r|\f/g, '');
}

// ========================
// 存储
// ========================

function hasLinkDb(env) {
  return Boolean(env.LINK_DB && typeof env.LINK_DB.prepare === 'function');
}

function hasLinkKv(env) {
  return Boolean(linkKv(env));
}

function linkKv(env) {
  const store = env.LINK_KV || env.LINK_STORE;
  if (store && typeof store.get === 'function' && typeof store.put === 'function') return store;
  return null;
}

async function ensureLinkDb(env) {
  if (!hasLinkDb(env)) return;
  if (typeof env.LINK_DB.exec === 'function') {
    await env.LINK_DB.exec(
      `CREATE TABLE IF NOT EXISTS links (
        id TEXT PRIMARY KEY,
        payload_hash TEXT NOT NULL,
        expires_at INTEGER,
        created_at INTEGER NOT NULL,
        password_hash TEXT DEFAULT NULL
      )`
    );
  }
}

// ========================
// 认证与Cookie
// ========================

async function isAuthorized(request, env) {
  if (!readText(env.ACCESS_PASSWORD)) return true;
  const cookie = getCookie(request.headers.get('Cookie') || '', 'sg_session');
  if (!cookie) return false;
  return verifySessionCookie(cookie, env);
}

function getCookie(header, name) {
  const prefix = `${name}=`;
  return header.split(';').map(p => p.trim()).find(p => p.startsWith(prefix))?.slice(prefix.length);
}

async function createSessionCookie(request, env) {
  const expiresAt = Math.floor(Date.now() / 1000) + 12 * 60 * 60;
  const payload = base64UrlEncode(encoder.encode(JSON.stringify({ exp: expiresAt })));
  const signature = await sign(payload, authSecret(env), 'SHA-256');
  return sessionCookie(`${payload}.${signature}`, request, 'Max-Age=43200');
}

async function verifySessionCookie(cookie, env) {
  const [payload, signature] = cookie.split('.');
  if (!payload || !signature) return false;
  const expected = await sign(payload, authSecret(env), 'SHA-256');
  if (!constantTimeEqual(signature, expected)) return false;
  try {
    const session = JSON.parse(decoder.decode(base64UrlDecode(payload)));
    return Number.isFinite(session.exp) && session.exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}

function sessionCookie(value, request, maxAge) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `sg_session=${value}; ${maxAge}; Path=/; HttpOnly; SameSite=Strict${secure}`;
}

async function sign(value, secret, hash) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash }, false, ['sign']);
  const digest = await crypto.subtle.sign('HMAC', key, encoder.encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function authSecret(env) {
  return readText(env.SESSION_SECRET) || readText(env.ACCESS_PASSWORD);
}

// ========================
// API 处理
// ========================

async function handleLogin(request, env) {
  const expected = readText(env.ACCESS_PASSWORD);
  if (!expected) return json({ ok: true, authRequired: false });
  let body;
  try { body = await request.json(); } catch { return json({ error: 'bad_request' }, 400); }
  const pw = typeof body.password === 'string' ? body.password : '';
  if (!constantTimeEqual(pw, expected)) return json({ error: 'unauthorized', message: 'Wrong password.' }, 401);
  return json({ ok: true, authRequired: true }, 200, { 'Set-Cookie': await createSessionCookie(request, env) });
}

function handleLogout(request) {
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', request, 'Max-Age=0') });
}

async function handleRegisterLink(request, env) {
  if (!(await isAuthorized(request, env))) return json({ error: 'unauthorized', message: 'Password required.' }, 401);

  const requireSecret = linkSecretRequired(env);
  const secret = linkSecret(env);
  if (requireSecret && !secret) return json({ error: 'server_misconfigured', message: 'LINK_SECRET missing.' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'bad_request' }, 400); }

  const clientPayload = readText(body.payload);
  if (!clientPayload || !/^[A-Za-z0-9_-]+$/.test(clientPayload)) return json({ error: 'bad_request', message: 'Invalid payload.' }, 400);

  const customTtl = readText(body.ttlMinutes);
  const ttlMinutes = customTtl ? Number(customTtl) : linkTtlMinutes(env);
  const ttlSeconds = ttlMinutes === 0 ? 0 : Math.max(60, Math.floor(ttlMinutes * 60));
  const expiresAt = ttlSeconds === 0 ? null : Math.floor(Date.now() / 1000) + ttlSeconds;

  const linkPassword = readText(body.linkPassword);
  const passwordHash = linkPassword ? await sha256Base64Url(linkPassword) : null;

  const storage = hasLinkDb(env) ? 'd1' : hasLinkKv(env) ? 'kv' : 'stateless';
  const id = storage === 'stateless' ? '0' : randomId();
  const linkPayload = secret ? await sealServerLinkPayload(clientPayload, id, secret) : clientPayload;
  const path = `/${id}.${linkPayload}`;
  const payloadHash = await sha256Base64Url(linkPayload);

  if (storage === 'd1') {
    await ensureLinkDb(env);
    await env.LINK_DB.prepare(
      'INSERT OR REPLACE INTO links (id, payload_hash, expires_at, created_at, password_hash) VALUES (?1, ?2, ?3, ?4, ?5)'
    ).bind(id, payloadHash, expiresAt, Math.floor(Date.now() / 1000), passwordHash).run();
    return json({ path, expiresAt, ttlSeconds, storage: 'd1', serverSecret: Boolean(secret) });
  }

  if (storage === 'kv') {
    const record = JSON.stringify({ hash: payloadHash, expiresAt, passwordHash });
    const options = ttlSeconds === 0 ? {} : { expirationTtl: ttlSeconds };
    await linkKv(env).put(id, record, options);
    return json({ path, expiresAt, ttlSeconds, storage: 'kv', serverSecret: Boolean(secret) });
  }

  return json({ path, expiresAt, ttlSeconds, storage: 'stateless', serverSecret: Boolean(secret) });
}

async function handleToken(request, env) {
  if (!(await isAuthorized(request, env))) return json({ error: 'unauthorized' }, 401);

  const requireSecret = linkSecretRequired(env);
  const secret = linkSecret(env);
  if (requireSecret && !secret) return json({ error: 'server_misconfigured', message: 'LINK_SECRET missing.' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'bad_request' }, 400); }

  const id = readText(body.id);
  const linkPayload = readText(body.payload);
  const keyText = readText(body.key);
  if (!id || !linkPayload || !keyText) return json({ error: 'bad_request', message: 'Missing parameters.' }, 400);

  const validation = await validateLink(id, linkPayload, env);
  if (!validation.ok) return json({ error: 'expired', message: validation.message }, 410);

  if (validation.passwordHash) {
    const inputPw = readText(body.linkPassword);
    if (!inputPw) return json({ error: 'password_required' }, 401);
    const inputHash = await sha256Base64Url(inputPw);
    if (!constantTimeEqual(inputHash, validation.passwordHash)) {
      return json({ error: 'wrong_password', message: 'Link password incorrect.' }, 401);
    }
  }

  let clientPayload;
  try { clientPayload = await openServerLinkPayload(linkPayload, id, env); } catch (e) { return json({ error: 'bad_link', message: e.message }, 400); }

  let account;
  try { account = await unsealClientPayload(clientPayload, keyText); } catch { return json({ error: 'bad_link' }, 400); }

  if (!account || account.v !== 1 || !account.sharedSecret) return json({ error: 'bad_link' }, 400);
  if (account.expiresAt && account.expiresAt <= Math.floor(Date.now() / 1000)) return json({ error: 'expired' }, 410);

  const now = Date.now();
  const windowInfo = getSteamTimeWindow(now);
  const token = await generateSteamGuardCode(account.sharedSecret, now);

  return json({
    name: account.name || 'Steam',
    token,
    period: windowInfo.period,
    secondsRemaining: windowInfo.secondsRemaining,
    serverTime: windowInfo.serverTime,
    nextRefreshAt: windowInfo.nextRefreshAt,
  });
}

// ========================
// 链接验证（返回密码哈希）
// ========================

async function validateLink(id, payload, env) {
  if (!/^[A-Za-z0-9_-]+$/.test(id) || !/^[A-Za-z0-9_-]+$/.test(payload)) return { ok: false, message: 'Invalid format.' };
  if (id === '0') return { ok: true, passwordHash: null };

  if (!hasLinkDb(env)) {
    if (hasLinkKv(env)) return validateKvLink(id, payload, env);
    return { ok: false, message: 'Cannot verify link.' };
  }

  await ensureLinkDb(env);
  const row = await env.LINK_DB.prepare('SELECT payload_hash, expires_at, password_hash FROM links WHERE id = ?1').bind(id).first();
  if (!row) return { ok: false, message: 'Link expired or revoked.' };

  const expiresAt = Number(row.expires_at || 0);
  if (expiresAt && expiresAt <= Math.floor(Date.now() / 1000)) {
    await env.LINK_DB.prepare('DELETE FROM links WHERE id = ?1').bind(id).run();
    return { ok: false, message: 'Link expired.' };
  }

  const expectedHash = readText(row.payload_hash);
  const actualHash = await sha256Base64Url(payload);
  if (!constantTimeEqual(expectedHash, actualHash)) return { ok: false, message: 'Payload mismatch.' };

  const passwordHash = readText(row.password_hash) || null;
  return { ok: true, passwordHash };
}

async function validateKvLink(id, payload, env) {
  const record = await linkKv(env).get(id, 'json');
  if (!record) return { ok: false, message: 'Link expired or revoked.' };

  const expiresAt = Number(record.expiresAt || 0);
  if (expiresAt && expiresAt <= Math.floor(Date.now() / 1000)) {
    await linkKv(env).delete(id);
    return { ok: false, message: 'Link expired.' };
  }

  const expectedHash = readText(record.hash);
  const actualHash = await sha256Base64Url(payload);
  if (!constantTimeEqual(expectedHash, actualHash)) return { ok: false, message: 'Payload mismatch.' };

  const passwordHash = readText(record.passwordHash) || null;
  return { ok: true, passwordHash };
}

// ========================
// 服务端二次加密
// ========================

function linkSecret(env) { return readText(env.LINK_SECRET) || readText(env.SERVER_SECRET); }
function linkSecretRequired(env) { return ['1','true','yes','on'].includes(readText(env.REQUIRE_LINK_SECRET).toLowerCase()); }

function isServerSealedPayload(payload) {
  try { const p = base64UrlDecode(payload); return p.length > 0 && p[0] === 2; } catch { return false; }
}

async function openServerLinkPayload(linkPayload, id, env) {
  if (isServerSealedPayload(linkPayload)) {
    const s = linkSecret(env);
    if (!s) throw new Error('LINK_SECRET not configured.');
    return unsealServerLinkPayload(linkPayload, id, s);
  }
  if (linkSecretRequired(env)) throw new Error('Legacy link without LINK_SECRET.');
  return linkPayload;
}

async function sealServerLinkPayload(clientPayload, id, secret) {
  const salt = new Uint8Array(16); crypto.getRandomValues(salt);
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  const key = await deriveServerLinkKey(secret, id, salt);
  const plaintext = encoder.encode(JSON.stringify({ v: 1, p: clientPayload }));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: serverLinkAad(id) }, key, plaintext));
  const packed = new Uint8Array(1 + salt.length + iv.length + ciphertext.length);
  packed[0] = 2; packed.set(salt, 1); packed.set(iv, 17); packed.set(ciphertext, 29);
  return base64UrlEncode(packed);
}

async function unsealServerLinkPayload(linkPayload, id, secret) {
  const packed = base64UrlDecode(linkPayload);
  if (packed.length < 46 || packed[0] !== 2) throw new Error('Invalid server sealed format.');
  const salt = packed.slice(1, 17), iv = packed.slice(17, 29), ciphertext = packed.slice(29);
  const key = await deriveServerLinkKey(secret, id, salt);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: serverLinkAad(id) }, key, ciphertext);
  const envelope = JSON.parse(decoder.decode(plaintext));
  if (envelope.v !== 1 || !/^[A-Za-z0-9_-]+$/.test(readText(envelope.p))) throw new Error('Invalid envelope.');
  return envelope.p;
}

async function deriveServerLinkKey(secret, id, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(`steam-guard-link-worker:server-link-key:v1:${id}`) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function serverLinkAad(id) { return encoder.encode(`steam-guard-link-worker:server-link-payload:v1:${id}`); }

// ========================
// 客户端密封
// ========================

async function unsealClientPayload(payload, keyText) {
  const packed = base64UrlDecode(payload);
  const rawKey = base64UrlDecode(keyText);
  if (packed.length < 30 || packed[0] !== 1 || rawKey.length !== 32) throw new Error('Invalid client sealed format.');
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: packed.slice(1, 13) }, key, packed.slice(13));
  return JSON.parse(decoder.decode(plaintext));
}

// ========================
// Steam Guard 生成
// ========================

async function generateSteamGuardCode(sharedSecret, now = Date.now()) {
  const secretBytes = base64ToBytes(sharedSecret);
  const counter = Math.floor(Math.floor(now / 1000) / 30);
  const message = counterToBytes(counter);
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = digest[digest.length - 1] & 0x0f;
  let codePoint = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
  const steamChars = '23456789BCDFGHJKMNPQRTVWXY';
  let code = '';
  for (let i = 0; i < 5; i++) { code += steamChars[codePoint % steamChars.length]; codePoint = Math.floor(codePoint / steamChars.length); }
  return code;
}

function getSteamTimeWindow(now = Date.now()) {
  const serverTime = Math.floor(now / 1000);
  const elapsed = serverTime % 30;
  const secondsRemaining = elapsed === 0 ? 30 : 30 - elapsed;
  return { period: 30, serverTime, secondsRemaining, nextRefreshAt: serverTime + secondsRemaining };
}

function counterToBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) { bytes[i] = Number(value & 0xffn); value >>= 8n; }
  return bytes;
}

// ========================
// HTML 页面
// ========================

function renderLoginPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Steam Guard Link</title>
  <style nonce="__NONCE__">
    :root { color-scheme:light; --bg:#f7a7c7; --bg-image:__BACKGROUND_IMAGE__; --panel:#fff4f8; --ink:#351323; --muted:#75566a; --accent:#d93682; --bad:#a7335b; }
    * { box-sizing:border-box; } body { margin:0; min-height:100vh; background:linear-gradient(145deg,rgba(255,244,248,.72),transparent 36%),linear-gradient(315deg,rgba(217,54,130,.22),transparent 42%),var(--bg-image),var(--bg); background-size:auto,auto,cover,auto; background-position:center; background-attachment:fixed; color:var(--ink); font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(430px,calc(100vw - 32px)); min-height:100vh; margin:0 auto; display:grid; align-content:center; gap:18px; }
    h1 { margin:0; font-size:2.5rem; line-height:1; }
    .panel { border-radius:14px; background:var(--panel); box-shadow:0 24px 80px rgba(96,24,57,.24); padding:24px; display:grid; gap:12px; }
    label { color:var(--muted); font-size:.92rem; }
    input { width:100%; min-height:44px; border:1px solid rgba(53,19,35,.16); border-radius:10px; background:white; color:var(--ink); padding:0 12px; font:inherit; }
    button { min-height:44px; border:0; border-radius:10px; background:var(--accent); color:white; font-weight:720; cursor:pointer; font:inherit; }
    button:hover,button:focus-visible { background:#b8246b; }
    .error { min-height:22px; color:var(--bad); font-size:.9rem; }
  </style>
</head>
<body>
  <main>
    <h1>Steam Guard Link</h1>
    <section class="panel">
      <label for="password">访问密码</label>
      <input id="password" type="password" autocomplete="current-password" placeholder="输入访问密码">
      <button id="login" type="button">进入</button>
      <span id="error" class="error"></span>
    </section>
  </main>
  <script nonce="__NONCE__">
    const passwordEl = document.getElementById("password");
    const loginEl = document.getElementById("login");
    const errorEl = document.getElementById("error");
    async function login() {
      errorEl.textContent = ""; loginEl.disabled = true; loginEl.textContent = "验证中";
      try {
        const res = await fetch("/api/login", { method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: passwordEl.value }) });
        if (!res.ok) throw new Error("密码不正确");
        location.reload();
      } catch (e) { errorEl.textContent = e.message || "密码不正确"; }
      finally { loginEl.disabled = false; loginEl.textContent = "进入"; }
    }
    loginEl.addEventListener("click", login);
    passwordEl.addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
    passwordEl.focus();
  </script>
</body>
</html>`;
}

function renderApp() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Steam Guard Link</title>
  <style nonce="__NONCE__">
    :root { color-scheme:light; --bg:#f7a7c7; --bg-image:__BACKGROUND_IMAGE__; --panel:#fff4f8; --ink:#351323; --muted:#75566a; --accent:#d93682; --accent2:#a7335b; --line:rgba(53,19,35,.14); }
    * { box-sizing:border-box; } body { margin:0; min-height:100vh; background:linear-gradient(145deg,rgba(255,244,248,.72),transparent 36%),linear-gradient(315deg,rgba(217,54,130,.22),transparent 42%),var(--bg-image),var(--bg); background-size:auto,auto,cover,auto; background-position:center; background-attachment:fixed; color:var(--ink); font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    button,input,textarea { font:inherit; }
    main { width:min(780px,calc(100vw - 32px)); min-height:100vh; margin:0 auto; padding:40px 0; display:grid; align-content:center; gap:18px; }
    h1 { margin:0; font-size:3rem; line-height:1; }
    .sub { margin:8px 0 0; color:rgba(53,19,35,.72); }
    .panel,.card { border-radius:14px; background:var(--panel); color:var(--ink); box-shadow:0 24px 80px rgba(96,24,57,.24); padding:24px; display:grid; gap:14px; }
    label { color:var(--muted); font-size:.92rem; }
    input,textarea { width:100%; border:1px solid rgba(53,19,35,.16); border-radius:10px; background:white; color:var(--ink); padding:12px; }
    textarea { min-height:150px; resize:vertical; font-family:SFMono-Regular,Consolas,monospace; }
    button { min-height:44px; border:0; border-radius:10px; background:var(--accent); color:white; font-weight:720; cursor:pointer; }
    button:hover,button:focus-visible { background:#b8246b; }
    .result { display:none; gap:10px; }
    .result.visible { display:grid; }
    .row { display:grid; grid-template-columns:1fr 86px; gap:10px; }
    .error { min-height:22px; margin:0; color:var(--accent2); white-space:pre-wrap; }
    .note { margin:0; color:var(--muted); font-size:.9rem; line-height:1.5; }
    .top { display:flex; align-items:end; justify-content:space-between; gap:16px; }
    .status { min-width:112px; padding:10px 12px; border:1px solid rgba(53,19,35,.18); border-radius:10px; color:rgba(53,19,35,.82); text-align:center; background:rgba(255,244,248,.34); }
    .card { min-height:250px; grid-template-rows:auto 1fr auto; }
    .head { display:flex; align-items:center; justify-content:space-between; gap:14px; }
    .name { margin:0; color:var(--muted); overflow-wrap:anywhere; }
    .ring { width:46px; height:46px; flex:0 0 46px; border-radius:50%; display:grid; place-items:center; background:conic-gradient(var(--accent) 360deg,rgba(53,19,35,.1) 0); color:var(--ink); font-size:.78rem; font-weight:700; }
    .code { align-self:center; margin:0; font-family:SFMono-Regular,Consolas,monospace; font-size:5rem; line-height:1; font-weight:800; text-align:center; white-space:nowrap; }
    .actions { display:flex; align-items:center; gap:10px; border-top:1px solid var(--line); padding-top:16px; }
    .copy { min-width:96px; }
    .hidden { display:none; }
    .qrcode-img { max-width:200px; margin:0 auto; }
    @media (max-width:620px) { main { width:min(100vw - 24px,780px); } .top { align-items:start; flex-direction:column; } h1 { font-size:2.35rem; } .row { grid-template-columns:1fr; } .code { font-size:3.75rem; } }
  </style>
</head>
<body>
  <main>
    <section id="create-view">
      <div><h1>Steam Guard Link</h1><p class="sub">浏览器本地加密；可设置链接密码、自定义有效期。</p></div>
      <section class="panel">
        <label for="name-input">显示名称</label>
        <input id="name-input" autocomplete="off" placeholder="Steam">
        <label for="secret-input">Steam 密钥、maFile JSON 或 otpauth:// 链接</label>
        <textarea id="secret-input" spellcheck="false" placeholder="otpauth://totp/Steam:account?secret=...&issuer=Steam"></textarea>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
          <div><label for="ttl-input">有效期（分钟，0=永久）</label><input id="ttl-input" type="number" min="0" value="__LINK_TTL_MINUTES__" placeholder="分钟"></div>
          <div><label for="link-password-input">链接密码（可选）</label><input id="link-password-input" type="password" placeholder="留空则无密码"></div>
        </div>
        <button id="create-button" type="button">生成链接</button>
        <p id="create-error" class="error"></p>
        <div id="result" class="result">
          <label for="link-output">分享链接</label>
          <div class="row"><input id="link-output" readonly><button id="copy-link" type="button">复制</button></div>
          <img id="qrcode-img" class="qrcode-img" src="" alt="二维码" style="display:none;">
          <p id="result-note" class="note">完整链接本身就是访问凭证；不要公开截图、发 Issue、发日志。</p>
        </div>
      </section>
    </section>

    <section id="token-view" class="hidden">
      <section class="top"><h1>Steam Guard</h1><div id="status" class="status">同步中</div></section>
      <section class="card">
        <div class="head"><p id="account-name" class="name">Steam</p><div id="ring" class="ring">--</div></div>
        <p id="code" class="code">-----</p>
        <div class="actions"><button id="copy-code" class="copy" type="button">复制</button><span id="meta" class="note">30 秒刷新</span></div>
      </section>
      <section id="password-protect" class="panel hidden" style="margin-top:16px;">
        <label for="link-pass-input">此链接受密码保护</label>
        <input id="link-pass-input" type="password" placeholder="输入链接密码">
        <button id="link-pass-submit" type="button">确认</button>
        <p id="link-pass-error" class="error"></p>
      </section>
    </section>
  </main>

  <script nonce="__NONCE__">
    const PERIOD_SECONDS = 30;
    const LINK_TTL_MINUTES = Number("__LINK_TTL_MINUTES__") || 0;
    const encoder = new TextEncoder();

    const createView = document.getElementById("create-view");
    const tokenView = document.getElementById("token-view");
    const nameInput = document.getElementById("name-input");
    const secretInput = document.getElementById("secret-input");
    const ttlInput = document.getElementById("ttl-input");
    const linkPasswordInput = document.getElementById("link-password-input");
    const createButton = document.getElementById("create-button");
    const createError = document.getElementById("create-error");
    const result = document.getElementById("result");
    const linkOutput = document.getElementById("link-output");
    const copyLink = document.getElementById("copy-link");
    const qrcodeImg = document.getElementById("qrcode-img");
    const resultNote = document.getElementById("result-note");
    const statusEl = document.getElementById("status");
    const accountName = document.getElementById("account-name");
    const ring = document.getElementById("ring");
    const codeEl = document.getElementById("code");
    const copyCode = document.getElementById("copy-code");
    const meta = document.getElementById("meta");
    const passwordProtect = document.getElementById("password-protect");
    const linkPassInput = document.getElementById("link-pass-input");
    const linkPassSubmit = document.getElementById("link-pass-submit");
    const linkPassError = document.getElementById("link-pass-error");

    const state = { id: "", payload: "", key: "", token: "", timer: 0, period: 30, linkPassword: null };

    if (location.pathname !== "/") {
      createView.classList.add("hidden");
      tokenView.classList.remove("hidden");
      openSharedLink();
    }

    createButton.addEventListener("click", async () => {
      createError.textContent = ""; result.classList.remove("visible"); createButton.disabled = true; createButton.textContent = "生成中";
      try {
        const account = parseAccount(secretInput.value, nameInput.value);
        const ttl = ttlInput.value.trim();
        const linkPassword = linkPasswordInput.value.trim();
        const expiresAt = ttl === "0" ? null : Math.floor(Date.now() / 1000) + Math.max(60, Math.floor((Number(ttl) || LINK_TTL_MINUTES) * 60));
        const { payload, key } = await sealClientPayload({ ...account, expiresAt });
        const body = { payload, ttlMinutes: ttl };
        if (linkPassword) body.linkPassword = linkPassword;
        const res = await fetch("/api/register-link", { method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.message || "生成失败");
        const shareUrl = location.origin + data.path + "#" + key;
        linkOutput.value = shareUrl;
        qrcodeImg.src = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + encodeURIComponent(shareUrl);
        qrcodeImg.style.display = "block";
        resultNote.textContent = (data.serverSecret ? "已启用 LINK_SECRET 二次封装。" : "兼容模式。") + " 完整链接是访问凭证，请勿公开。";
        result.classList.add("visible");
      } catch (e) { createError.textContent = e.message || "生成失败"; }
      finally { createButton.disabled = false; createButton.textContent = "生成链接"; }
    });

    copyLink.addEventListener("click", () => copyText(linkOutput.value, copyLink, "已复制"));
    copyCode.addEventListener("click", () => copyText(state.token, copyCode, "已复制"));

    linkPassSubmit.addEventListener("click", async () => {
      linkPassError.textContent = "";
      state.linkPassword = linkPassInput.value.trim();
      if (!state.linkPassword) return;
      await refreshToken();
    });

    function showTokenView() { createView.classList.add("hidden"); tokenView.classList.remove("hidden"); }

    function parseAccount(raw, preferredName) {
      const input = String(raw || "").trim();
      if (!input) throw new Error("请粘贴 Steam 密钥、maFile JSON 或 otpauth:// 链接");
      let name = String(preferredName || "").trim();
      let secret = "";
      if (input.startsWith("otpauth://")) {
        const url = new URL(input);
        secret = url.searchParams.get("secret") || "";
        if (!name) {
          name = decodeURIComponent(url.pathname.replace(/^\\//, "")) || url.searchParams.get("issuer") || "Steam";
        }
      } else if (/^\\s*[{[]/.test(input)) {
        const data = JSON.parse(input);
        secret = data.shared_secret || data.sharedSecret || data.secret || "";
        if (!name) name = data.account_name || data.accountName || data.name || "Steam";
      } else {
        secret = input;
      }
      secret = String(secret || "").trim().replace(/\\s+/g, "");
      if (!secret) throw new Error("没有找到 Steam shared_secret / secret");
      const sharedSecret = normalizeSteamSecret(secret);
      return { v: 1, name: name || "Steam", sharedSecret };
    }

    function normalizeSteamSecret(secret) {
      if (/^[A-Z2-7]+=*$/i.test(secret) && !/[+/]/.test(secret)) return bytesToBase64(base32Decode(secret));
      const bytes = base64ToBytes(secret);
      if (!bytes.length) throw new Error("Steam 密钥格式不正确");
      return bytesToBase64(bytes);
    }

    async function sealClientPayload(account) {
      const rawKey = new Uint8Array(32); crypto.getRandomValues(rawKey);
      const iv = new Uint8Array(12); crypto.getRandomValues(iv);
      const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(account))));
      const packed = new Uint8Array(1 + iv.length + ciphertext.length);
      packed[0] = 1; packed.set(iv, 1); packed.set(ciphertext, 13);
      return { payload: base64UrlEncode(packed), key: base64UrlEncode(rawKey) };
    }

    async function openSharedLink() {
      const packed = location.pathname.slice(1);
      const dot = packed.indexOf(".");
      state.key = location.hash.slice(1);
      if (dot < 1 || !state.key) { statusEl.textContent = "链接无效"; codeEl.textContent = "-----"; return; }
      state.id = packed.slice(0, dot); state.payload = packed.slice(dot + 1);
      await refreshToken();
      clearInterval(state.timer);
      state.timer = setInterval(tick, 1000);
    }

    async function tick() {
      updateCountdown();
      const seconds = Number(ring.textContent);
      if (seconds === PERIOD_SECONDS || seconds <= 1) await refreshToken();
    }

    async function refreshToken() {
      try {
        const body = { id: state.id, payload: state.payload, key: state.key };
        if (state.linkPassword) body.linkPassword = state.linkPassword;
        const res = await fetch("/api/token", { method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const data = await res.json().catch(() => ({}));
        if (res.status === 401 && data.error === "password_required") {
          passwordProtect.classList.remove("hidden");
          passwordProtect.style.display = 'block';
          statusEl.textContent = "需要密码";
          codeEl.textContent = "-----";
          meta.textContent = "请输入链接密码";
          clearInterval(state.timer);
          return;
        }
        if (!res.ok) throw new Error(data.message || "链接不可用");
        passwordProtect.classList.add("hidden");
        state.token = data.token; state.period = data.period || PERIOD_SECONDS;
        codeEl.textContent = data.token; accountName.textContent = data.name || "Steam";
        statusEl.textContent = "可用"; meta.textContent = data.period + " 秒刷新";
        updateCountdown(data.secondsRemaining);
        if (!state.timer) state.timer = setInterval(tick, 1000);
      } catch (e) {
        statusEl.textContent = "不可用"; codeEl.textContent = "-----"; meta.textContent = e.message || "链接不可用";
      }
    }

    function updateCountdown(value) {
      const remaining = Number.isFinite(value) ? value : state.period - (Math.floor(Date.now() / 1000) % state.period);
      const safe = Math.max(1, Math.min(state.period, remaining));
      const degree = Math.round((safe / state.period) * 360);
      ring.textContent = String(safe).padStart(2, "0");
      ring.style.background = "conic-gradient(var(--accent) " + degree + "deg, rgba(53,19,35,.1) 0)";
    }

    async function copyText(text, btn, label) {
      if (!text) return;
      await navigator.clipboard.writeText(text);
      const old = btn.textContent; btn.textContent = label;
      setTimeout(() => { btn.textContent = old; }, 1200);
    }

    function base32Decode(value) {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const clean = value.toUpperCase().replace(/=+$/g, "");
      let bits = 0, valueBuffer = 0, out = [];
      for (const ch of clean) {
        const idx = alphabet.indexOf(ch);
        if (idx < 0) throw new Error("Base32 密钥格式不正确");
        valueBuffer = (valueBuffer << 5) | idx; bits += 5;
        if (bits >= 8) { out.push((valueBuffer >>> (bits - 8)) & 255); bits -= 8; }
      }
      return new Uint8Array(out);
    }

    function base64ToBytes(value) {
      const clean = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
      const binary = atob(clean);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }

    function bytesToBase64(bytes) {
      let binary = "";
      for (const b of bytes) binary += String.fromCharCode(b);
      return btoa(binary);
    }

    function base64UrlEncode(bytes) {
      return bytesToBase64(bytes).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
    }
  </script>
</body>
</html>`;
}
