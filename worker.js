const encoder = new TextEncoder();
const decoder = new TextDecoder();

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname.replace(/\/+$/, "") || "/";

      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204 });
      }

      if (pathname === "/api/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }

      if (pathname === "/api/logout" && request.method === "POST") {
        return handleLogout(request);
      }

      if (pathname === "/api/register-link" && request.method === "POST") {
        return await handleRegisterLink(request, env);
      }

      if (pathname === "/api/token" && request.method === "POST") {
        return await handleToken(request, env);
      }

      if (pathname === "/healthz" && request.method === "GET") {
        return new Response("ok", {
          headers: {
            "Cache-Control": "no-store",
            "Content-Type": "text/plain; charset=utf-8"
          }
        });
      }

      if (request.method === "GET" && isAppPath(pathname)) {
        if (!(await isAuthorized(request, env))) {
          return htmlResponse(renderLoginPage(), env);
        }
        return htmlResponse(renderApp(), env);
      }

      return json({ error: "not_found" }, 404);
    } catch (error) {
      return json(
        {
          error: "internal_error",
          message: error.message || "Unexpected server error."
        },
        500
      );
    }
  }
};

function isAppPath(pathname) {
  if (pathname === "/") {
    return true;
  }
  return /^\/[A-Za-z0-9_.-]+$/.test(pathname);
}

async function handleLogin(request, env) {
  const expectedPassword = readText(env.ACCESS_PASSWORD);
  if (!expectedPassword) {
    return json({ ok: true, authRequired: false });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "bad_request", message: "Invalid JSON body." }, 400);
  }

  const password = typeof body.password === "string" ? body.password : "";
  if (!constantTimeEqual(password, expectedPassword)) {
    return json({ error: "unauthorized", message: "Wrong password." }, 401);
  }

  return json({ ok: true, authRequired: true }, 200, {
    "Set-Cookie": await createSessionCookie(request, env)
  });
}

function handleLogout(request) {
  return json({ ok: true }, 200, {
    "Set-Cookie": sessionCookie("", request, "Max-Age=0")
  });
}

async function handleRegisterLink(request, env) {
  if (!(await isAuthorized(request, env))) {
    return json({ error: "unauthorized", message: "Password required." }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "bad_request", message: "Invalid JSON body." }, 400);
  }

  const payload = readText(body.payload);
  if (!payload || !/^[A-Za-z0-9_-]+$/.test(payload)) {
    return json({ error: "bad_request", message: "Invalid encrypted payload." }, 400);
  }

  const ttlMinutes = linkTtlMinutes(env);
  const ttlSeconds = ttlMinutes === 0 ? 0 : Math.max(60, Math.floor(ttlMinutes * 60));
  const expiresAt = ttlSeconds === 0 ? null : Math.floor(Date.now() / 1000) + ttlSeconds;

  if (hasLinkDb(env)) {
    await ensureLinkDb(env);
    const id = randomId();
    await env.LINK_DB.prepare(
      "INSERT OR REPLACE INTO links (id, payload_hash, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)"
    )
      .bind(id, await sha256Base64Url(payload), expiresAt, Math.floor(Date.now() / 1000))
      .run();

    return json({
      path: `/${id}.${payload}`,
      expiresAt,
      ttlSeconds,
      storage: "d1"
    });
  }

  if (hasLinkKv(env)) {
    const id = randomId();
    const record = JSON.stringify({
      hash: await sha256Base64Url(payload),
      expiresAt
    });
    const options = ttlSeconds === 0 ? {} : { expirationTtl: ttlSeconds };
    await linkKv(env).put(id, record, options);

    return json({
      path: `/${id}.${payload}`,
      expiresAt,
      ttlSeconds,
      storage: "kv"
    });
  }

  return json({
    path: `/0.${payload}`,
    expiresAt,
    ttlSeconds,
    storage: "stateless"
  });
}

async function handleToken(request, env) {
  if (!(await isAuthorized(request, env))) {
    return json({ error: "unauthorized", message: "Password required." }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "bad_request", message: "Invalid JSON body." }, 400);
  }

  const id = readText(body.id);
  const payload = readText(body.payload);
  const keyText = readText(body.key);
  if (!id || !payload || !keyText) {
    return json({ error: "bad_request", message: "Missing encrypted payload or key." }, 400);
  }
  const validation = await validateLink(id, payload, env);
  if (!validation.ok) {
    return json({ error: "expired", message: validation.message }, 410);
  }

  const account = await unsealClientPayload(payload, keyText);
  if (!account || account.v !== 1 || !account.sharedSecret) {
    return json({ error: "bad_link", message: "Encrypted link content is invalid." }, 400);
  }
  if (account.expiresAt && account.expiresAt <= Math.floor(Date.now() / 1000)) {
    return json({ error: "expired", message: "This link has expired." }, 410);
  }

  const now = Date.now();
  const windowInfo = getSteamTimeWindow(now);

  return json({
    name: account.name || "Steam",
    token: await generateSteamGuardCode(account.sharedSecret, now),
    period: windowInfo.period,
    secondsRemaining: windowInfo.secondsRemaining,
    serverTime: windowInfo.serverTime,
    nextRefreshAt: windowInfo.nextRefreshAt
  });
}

async function validateLink(id, payload, env) {
  if (!/^[A-Za-z0-9_-]+$/.test(id) || !/^[A-Za-z0-9_-]+$/.test(payload)) {
    return { ok: false, message: "Link format is invalid." };
  }

  if (id === "0") {
    return { ok: true };
  }

  if (!hasLinkDb(env)) {
    if (hasLinkKv(env)) {
      return validateKvLink(id, payload, env);
    }
    return { ok: false, message: "This database-backed link cannot be verified." };
  }

  await ensureLinkDb(env);
  const record = await env.LINK_DB.prepare(
    "SELECT payload_hash, expires_at FROM links WHERE id = ?1"
  )
    .bind(id)
    .first();

  if (!record) {
    return { ok: false, message: "This link has expired or was revoked." };
  }

  const expiresAt = Number(record.expires_at || 0);
  if (expiresAt && expiresAt <= Math.floor(Date.now() / 1000)) {
    await env.LINK_DB.prepare("DELETE FROM links WHERE id = ?1").bind(id).run();
    return { ok: false, message: "This link has expired." };
  }

  const expectedHash = readText(record.payload_hash);
  const actualHash = await sha256Base64Url(payload);
  if (!constantTimeEqual(expectedHash, actualHash)) {
    return { ok: false, message: "Encrypted payload does not match this link." };
  }

  return { ok: true };
}

async function validateKvLink(id, payload, env) {
  const record = await linkKv(env).get(id, "json");
  if (!record) {
    return { ok: false, message: "This link has expired or was revoked." };
  }

  const expiresAt = Number(record.expiresAt || 0);
  if (expiresAt && expiresAt <= Math.floor(Date.now() / 1000)) {
    await linkKv(env).delete(id);
    return { ok: false, message: "This link has expired." };
  }

  const expectedHash = readText(record.hash);
  const actualHash = await sha256Base64Url(payload);
  if (!constantTimeEqual(expectedHash, actualHash)) {
    return { ok: false, message: "Encrypted payload does not match this link." };
  }

  return { ok: true };
}

async function unsealClientPayload(payload, keyText) {
  let packed;
  let rawKey;
  try {
    packed = base64UrlDecode(payload);
    rawKey = base64UrlDecode(keyText);
  } catch {
    throw new Error("Encrypted link is not valid base64url.");
  }

  if (packed.length < 30 || packed[0] !== 1) {
    throw new Error("Encrypted link format is invalid.");
  }

  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: packed.slice(1, 13) },
    key,
    packed.slice(13)
  );
  return JSON.parse(decoder.decode(plaintext));
}

async function generateSteamGuardCode(sharedSecret, now = Date.now()) {
  const secretBytes = base64ToBytes(sharedSecret);
  if (!secretBytes.length) {
    throw new Error("shared_secret cannot be empty.");
  }

  const counter = Math.floor(Math.floor(now / 1000) / 30);
  const message = counterToBytes(counter);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1] & 0x0f;
  let codePoint =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const steamChars = "23456789BCDFGHJKMNPQRTVWXY";
  let code = "";
  for (let i = 0; i < 5; i += 1) {
    code += steamChars[codePoint % steamChars.length];
    codePoint = Math.floor(codePoint / steamChars.length);
  }
  return code;
}

function getSteamTimeWindow(now = Date.now()) {
  const serverTime = Math.floor(now / 1000);
  const elapsed = serverTime % 30;
  const secondsRemaining = elapsed === 0 ? 30 : 30 - elapsed;
  return {
    period: 30,
    serverTime,
    secondsRemaining,
    nextRefreshAt: serverTime + secondsRemaining
  };
}

function counterToBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

async function isAuthorized(request, env) {
  if (!readText(env.ACCESS_PASSWORD)) {
    return true;
  }

  const cookie = getCookie(request.headers.get("Cookie") || "", "sg_session");
  if (!cookie) {
    return false;
  }

  return verifySessionCookie(cookie, env);
}

async function createSessionCookie(request, env) {
  const expiresAt = Math.floor(Date.now() / 1000) + 12 * 60 * 60;
  const payload = base64UrlEncode(encoder.encode(JSON.stringify({ exp: expiresAt })));
  const signature = await sign(payload, authSecret(env), "SHA-256");
  return sessionCookie(`${payload}.${signature}`, request, "Max-Age=43200");
}

async function verifySessionCookie(cookie, env) {
  const parts = cookie.split(".");
  if (parts.length !== 2) {
    return false;
  }

  const [payload, signature] = parts;
  const expectedSignature = await sign(payload, authSecret(env), "SHA-256");
  if (!constantTimeEqual(signature, expectedSignature)) {
    return false;
  }

  try {
    const session = JSON.parse(decoder.decode(base64UrlDecode(payload)));
    return Number.isFinite(session.exp) && session.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function sign(value, secret, hash) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash },
    false,
    ["sign"]
  );
  const digest = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function authSecret(env) {
  return readText(env.SESSION_SECRET) || readText(env.ACCESS_PASSWORD);
}

function getCookie(header, name) {
  const prefix = `${name}=`;
  return header
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix))
    ?.slice(prefix.length);
}

function sessionCookie(value, request, maxAge) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `sg_session=${value}; ${maxAge}; Path=/; HttpOnly; SameSite=Strict${secure}`;
}

function constantTimeEqual(a, b) {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const max = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;

  for (let i = 0; i < max; i += 1) {
    diff |= (left[i] || 0) ^ (right[i] || 0);
  }

  return diff === 0;
}

function readText(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      ...headers
    }
  });
}

function htmlResponse(markup, env = {}) {
  const nonce = randomNonce();
  return new Response(
    markup
      .replaceAll("__NONCE__", nonce)
      .replaceAll("__BACKGROUND_IMAGE__", backgroundImageValue(env))
      .replaceAll("__LINK_TTL_MINUTES__", String(linkTtlMinutes(env))),
    {
      headers: {
        "Cache-Control": "no-store",
        "Content-Security-Policy": [
          "default-src 'self'",
          "base-uri 'none'",
          "connect-src 'self'",
          "form-action 'self'",
          "frame-ancestors 'none'",
          "img-src 'self' data: https: http:",
          `style-src 'nonce-${nonce}'`,
          `script-src 'nonce-${nonce}'`
        ].join("; "),
        "Content-Type": "text/html; charset=utf-8",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff"
      }
    }
  );
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

function linkTtlMinutes(env) {
  const raw = readText(env.LINK_TTL_MINUTES);
  if (!raw) {
    return 30;
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    return 30;
  }
  return value;
}

function hasLinkDb(env) {
  return Boolean(env.LINK_DB && typeof env.LINK_DB.prepare === "function");
}

function hasLinkKv(env) {
  return Boolean(linkKv(env));
}

function linkKv(env) {
  const store = env.LINK_KV || env.LINK_STORE;
  if (store && typeof store.get === "function" && typeof store.put === "function") {
    return store;
  }
  return null;
}

async function ensureLinkDb(env) {
  if (!hasLinkDb(env)) {
    return;
  }

  if (typeof env.LINK_DB.exec === "function") {
    await env.LINK_DB.exec(
      "CREATE TABLE IF NOT EXISTS links (" +
        "id TEXT PRIMARY KEY, " +
        "payload_hash TEXT NOT NULL, " +
        "expires_at INTEGER, " +
        "created_at INTEGER NOT NULL" +
      ")"
    );
  }
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function backgroundImageValue(env) {
  const url = readText(env.BACKGROUND_IMAGE_URL);
  return url ? `url("${cssString(url)}")` : "none";
}

function cssString(value) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n|\r|\f/g, "");
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "="
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64ToBytes(value) {
  const binary = atob(value.trim().replace(/\s+/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function renderLoginPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Steam Guard Link</title>
  <style nonce="__NONCE__">
    :root { color-scheme:light; --bg:#f7a7c7; --bg-image:__BACKGROUND_IMAGE__; --panel:#fff4f8; --ink:#351323; --muted:#75566a; --accent:#d93682; --bad:#a7335b; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:linear-gradient(145deg,rgba(255,244,248,.72),transparent 36%),linear-gradient(315deg,rgba(217,54,130,.22),transparent 42%),var(--bg-image),var(--bg); background-size:auto,auto,cover,auto; background-position:center; background-attachment:fixed; color:var(--ink); font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; letter-spacing:0; }
    button,input { font:inherit; letter-spacing:0; }
    main { width:min(430px,calc(100vw - 32px)); min-height:100vh; margin:0 auto; display:grid; align-content:center; gap:18px; }
    h1 { margin:0; font-size:2.5rem; line-height:1; }
    .panel { border-radius:8px; background:var(--panel); box-shadow:0 24px 80px rgba(96,24,57,.24); padding:24px; display:grid; gap:12px; }
    label { color:var(--muted); font-size:.92rem; }
    input { width:100%; min-height:44px; border:1px solid rgba(53,19,35,.16); border-radius:8px; background:white; color:var(--ink); padding:0 12px; }
    button { min-height:44px; border:0; border-radius:8px; background:var(--accent); color:white; font-weight:720; cursor:pointer; }
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
      errorEl.textContent = "";
      loginEl.disabled = true;
      loginEl.textContent = "验证中";
      try {
        const response = await fetch("/api/login", {
          method: "POST",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: passwordEl.value })
        });
        if (!response.ok) throw new Error("密码不正确");
        location.reload();
      } catch (error) {
        errorEl.textContent = error.message || "密码不正确";
      } finally {
        loginEl.disabled = false;
        loginEl.textContent = "进入";
      }
    }

    loginEl.addEventListener("click", login);
    passwordEl.addEventListener("keydown", (event) => {
      if (event.key === "Enter") login();
    });
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
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:linear-gradient(145deg,rgba(255,244,248,.72),transparent 36%),linear-gradient(315deg,rgba(217,54,130,.22),transparent 42%),var(--bg-image),var(--bg); background-size:auto,auto,cover,auto; background-position:center; background-attachment:fixed; color:var(--ink); font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; letter-spacing:0; }
    button,input,textarea { font:inherit; letter-spacing:0; }
    main { width:min(760px,calc(100vw - 32px)); min-height:100vh; margin:0 auto; padding:40px 0; display:grid; align-content:center; gap:18px; }
    h1 { margin:0; font-size:3rem; line-height:1; }
    .sub { margin:8px 0 0; color:rgba(53,19,35,.72); }
    .panel,.card { border-radius:8px; background:var(--panel); color:var(--ink); box-shadow:0 24px 80px rgba(96,24,57,.24); padding:24px; display:grid; gap:14px; }
    label { color:var(--muted); font-size:.92rem; }
    input,textarea { width:100%; border:1px solid rgba(53,19,35,.16); border-radius:8px; background:white; color:var(--ink); padding:12px; }
    textarea { min-height:150px; resize:vertical; font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace; }
    button { min-height:44px; border:0; border-radius:8px; background:var(--accent); color:white; font-weight:720; cursor:pointer; }
    button:hover,button:focus-visible { background:#b8246b; }
    .result { display:none; gap:10px; }
    .result.visible { display:grid; }
    .row { display:grid; grid-template-columns:1fr 86px; gap:10px; }
    .error { min-height:22px; margin:0; color:var(--accent2); }
    .note { margin:0; color:var(--muted); font-size:.9rem; line-height:1.5; }
    .top { display:flex; align-items:end; justify-content:space-between; gap:16px; }
    .status { min-width:112px; min-height:40px; padding:10px 12px; border:1px solid rgba(53,19,35,.18); border-radius:8px; color:rgba(53,19,35,.82); text-align:center; background:rgba(255,244,248,.34); }
    .card { min-height:250px; grid-template-rows:auto 1fr auto; }
    .head { display:flex; align-items:center; justify-content:space-between; gap:14px; }
    .name { margin:0; color:var(--muted); overflow-wrap:anywhere; }
    .ring { width:46px; height:46px; flex:0 0 46px; border-radius:50%; display:grid; place-items:center; background:conic-gradient(var(--accent) 360deg,rgba(53,19,35,.1) 0); color:var(--ink); font-size:.78rem; font-weight:700; }
    .code { align-self:center; margin:0; font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace; font-size:5rem; line-height:1; font-weight:800; text-align:center; white-space:nowrap; }
    .actions { display:flex; align-items:center; gap:10px; border-top:1px solid var(--line); padding-top:16px; }
    .copy { min-width:96px; }
    .hidden { display:none; }
    @media (max-width:620px) { main { width:min(100vw - 24px,760px); } .top { align-items:start; flex-direction:column; } h1 { font-size:2.35rem; } .row { grid-template-columns:1fr; } .code { font-size:3.75rem; } }
  </style>
</head>
<body>
  <main>
    <section id="create-view">
      <div>
        <h1>Steam Guard Link</h1>
        <p class="sub">浏览器本地加密，生成 /id.密文#钥匙 分享链接。</p>
      </div>
      <section class="panel">
        <label for="name-input">显示名称</label>
        <input id="name-input" autocomplete="off" placeholder="Steam">
        <label for="secret-input">Steam 密钥、maFile JSON 或 otpauth:// 链接</label>
        <textarea id="secret-input" spellcheck="false" placeholder="otpauth://totp/Steam:account?secret=...&issuer=Steam"></textarea>
        <button id="create-button" type="button">生成链接</button>
        <p id="create-error" class="error"></p>
        <div id="result" class="result">
          <label for="link-output">分享链接</label>
          <div class="row">
            <input id="link-output" readonly>
            <button id="copy-link" type="button">复制</button>
          </div>
          <p class="note">Worker 只在请求期间临时解密并返回验证码，不存储 Steam 密钥。完整链接本身就是访问凭证。请勿分享给不可信的人，账号风险由使用者自行承担。</p>
        </div>
      </section>
    </section>

    <section id="token-view" class="hidden">
      <section class="top">
        <h1>Steam Guard</h1>
        <div id="status" class="status">同步中</div>
      </section>
      <section class="card">
        <div class="head">
          <p id="account-name" class="name">Steam</p>
          <div id="ring" class="ring">--</div>
        </div>
        <p id="code" class="code">-----</p>
        <div class="actions">
          <button id="copy-code" class="copy" type="button">复制</button>
          <span id="meta" class="note">30 秒刷新</span>
        </div>
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
    const createButton = document.getElementById("create-button");
    const createError = document.getElementById("create-error");
    const result = document.getElementById("result");
    const linkOutput = document.getElementById("link-output");
    const copyLink = document.getElementById("copy-link");
    const statusEl = document.getElementById("status");
    const accountName = document.getElementById("account-name");
    const ring = document.getElementById("ring");
    const codeEl = document.getElementById("code");
    const copyCode = document.getElementById("copy-code");
    const meta = document.getElementById("meta");

    const state = { id: "", payload: "", key: "", token: "", timer: 0, clockOffsetMs: 0, period: 30 };

    if (location.pathname !== "/") {
      showTokenView();
      openSharedLink();
    }

    createButton.addEventListener("click", async () => {
      createError.textContent = "";
      result.classList.remove("visible");
      createButton.disabled = true;
      createButton.textContent = "生成中";
      try {
        const account = parseSteamInput(secretInput.value, nameInput.value);
        account.expiresAt =
          LINK_TTL_MINUTES === 0
            ? null
            : Math.floor(Date.now() / 1000) + Math.max(60, Math.floor(LINK_TTL_MINUTES * 60));
        const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(account))));
        const packed = new Uint8Array(1 + iv.length + ciphertext.length);
        packed[0] = 1;
        packed.set(iv, 1);
        packed.set(ciphertext, 13);
        const payload = base64UrlEncode(packed);
        const keyText = base64UrlEncode(rawKey);
        const response = await fetch("/api/register-link", {
          method: "POST",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload })
        });
        const registered = await response.json();
        if (!response.ok) throw new Error(registered.message || "链接登记失败");
        linkOutput.value = location.origin + registered.path + "#" + keyText;
        result.classList.add("visible");
      } catch (error) {
        createError.textContent = error.message || "生成失败";
      } finally {
        createButton.disabled = false;
        createButton.textContent = "生成链接";
      }
    });

    copyLink.addEventListener("click", async () => {
      await navigator.clipboard.writeText(linkOutput.value);
      copyLink.textContent = "已复制";
      setTimeout(() => { copyLink.textContent = "复制"; }, 1200);
    });

    copyCode.addEventListener("click", async () => {
      await navigator.clipboard.writeText(state.token);
      statusEl.textContent = "已复制";
    });

    setInterval(updateCountdown, 250);

    function showTokenView() {
      createView.classList.add("hidden");
      tokenView.classList.remove("hidden");
    }

    async function openSharedLink() {
      try {
        const path = location.pathname.slice(1);
        const separator = path.indexOf(".");
        if (separator === -1) throw new Error("链接格式无效。");
        state.id = path.slice(0, separator);
        state.payload = path.slice(separator + 1);
        state.key = location.hash.replace(/^#/, "");
        if (!state.id || !state.payload || !state.key) throw new Error("链接缺少解密钥，请复制完整链接。");
        await fetchToken();
      } catch (error) {
        statusEl.textContent = "错误";
        meta.textContent = error.message || "链接无效";
        meta.classList.add("error");
      }
    }

    async function fetchToken() {
      try {
        statusEl.textContent = "同步中";
        const response = await fetch("/api/token", {
          method: "POST",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: state.id, payload: state.payload, key: state.key })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "链接无效");
        state.clockOffsetMs = data.serverTime * 1000 - Date.now();
        state.period = data.period || PERIOD_SECONDS;
        state.token = data.token || "";
        accountName.textContent = data.name || "Steam";
        codeEl.textContent = state.token || "-----";
        meta.textContent = "30 秒刷新";
        meta.classList.remove("error");
        statusEl.textContent = "已同步";
        updateCountdown();
        clearTimeout(state.timer);
        state.timer = setTimeout(fetchToken, Math.max(1, data.secondsRemaining || 1) * 1000 + 350);
      } catch (error) {
        statusEl.textContent = "错误";
        codeEl.textContent = "-----";
        meta.textContent = error.message || "链接无效";
        meta.classList.add("error");
        clearTimeout(state.timer);
        state.timer = setTimeout(fetchToken, 10000);
      }
    }

    function updateCountdown() {
      if (!state.payload) return;
      const serverNow = Math.floor((Date.now() + state.clockOffsetMs) / 1000);
      const elapsed = serverNow % state.period;
      const remaining = elapsed === 0 ? state.period : state.period - elapsed;
      const progress = Math.max(0, Math.min(1, remaining / state.period));
      ring.textContent = remaining + "s";
      ring.style.background = "conic-gradient(var(--accent) " + progress * 360 + "deg, rgba(53,19,35,.1) 0)";
    }

    function parseSteamInput(input, fallbackName) {
      const trimmed = input.trim();
      if (!trimmed) throw new Error("请粘贴 Steam 密钥。");
      if (trimmed.toLowerCase().startsWith("otpauth://")) return parseOtpAuthUri(trimmed);
      try {
        const parsed = JSON.parse(trimmed);
        const entry = Array.isArray(parsed) ? parsed[0] : parsed.accounts ? parsed.accounts[0] : parsed;
        if (!entry || typeof entry !== "object") throw new Error("JSON 格式不支持。");
        const uri = readText(entry.otpauth_url) || readText(entry.otpauthUrl) || readText(entry.uri);
        if (uri.toLowerCase().startsWith("otpauth://")) {
          const account = parseOtpAuthUri(uri);
          account.name = readText(entry.account_name) || readText(entry.accountName) || readText(entry.name) || account.name;
          return account;
        }
        const base32Secret = readText(entry.secret_base32) || readText(entry.base32_secret) || readText(entry.base32Secret);
        const sharedSecret = readText(entry.shared_secret) || readText(entry.sharedSecret) || (base32Secret ? bytesToBase64(base32ToBytes(base32Secret)) : "");
        if (!sharedSecret) throw new Error("JSON 里缺少 shared_secret。");
        return { v: 1, name: readText(entry.account_name) || readText(entry.accountName) || readText(entry.name) || fallbackName.trim() || "Steam", sharedSecret };
      } catch {
        const looksBase32 = /^[A-Z2-7]+=*$/i.test(trimmed) && !/[+/]/.test(trimmed);
        return { v: 1, name: fallbackName.trim() || "Steam", sharedSecret: looksBase32 ? bytesToBase64(base32ToBytes(trimmed)) : trimmed };
      }
    }

    function parseOtpAuthUri(value) {
      let url;
      try {
        url = new URL(value);
      } catch {
        throw new Error("otpauth 链接无效。");
      }
      if (url.protocol !== "otpauth:" || url.hostname !== "totp") throw new Error("只支持 otpauth://totp/... 链接。");
      const secret = url.searchParams.get("secret");
      if (!secret) throw new Error("otpauth 链接缺少 secret。");
      const rawLabel = decodeURIComponent(url.pathname.replace(/^\\/+/, ""));
      const match = rawLabel.match(/^[^:]+:(.+)$/);
      const issuer = url.searchParams.get("issuer") || "";
      return { v: 1, name: (match && match[1]) || rawLabel || issuer || "Steam", sharedSecret: bytesToBase64(base32ToBytes(secret)) };
    }

    function base32ToBytes(value) {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const cleaned = value.toUpperCase().replace(/=+$/g, "").replace(/\\s+/g, "");
      const output = [];
      let bits = 0;
      let buffer = 0;
      for (const char of cleaned) {
        const index = alphabet.indexOf(char);
        if (index === -1) throw new Error("Base32 密钥包含非法字符。");
        buffer = (buffer << 5) | index;
        bits += 5;
        if (bits >= 8) {
          output.push((buffer >> (bits - 8)) & 0xff);
          bits -= 8;
        }
      }
      return Uint8Array.from(output);
    }

    function bytesToBase64(bytes) {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary);
    }

    function base64UrlEncode(bytes) {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    }

    function readText(value) {
      return typeof value === "string" && value.trim() ? value.trim() : "";
    }
  </script>
</body>
</html>`;
}
