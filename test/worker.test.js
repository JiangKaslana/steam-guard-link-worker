import assert from "node:assert/strict";
import test from "node:test";

import worker from "../worker.js";

test("serves the app without any required secrets", async () => {
  const response = await worker.fetch(new Request("https://example.com/"), {});
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /Steam Guard Link/);
  assert.match(body, /id\.密文#钥匙/);
  assert.doesNotMatch(body, /LINK_SECRET/);
});

test("serves shared-link routes without server-side decryption", async () => {
  const response = await worker.fetch(new Request("https://example.com/linkId.abcDEF_123"), {});
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /openSharedLink/);
  assert.match(body, /location.hash/);
  assert.match(body, /api\/token/);
  assert.doesNotMatch(body, /function generateSteamGuardCode/);
});

test("decrypts encrypted link payload server-side and returns only a Steam token", async () => {
  const { payload, key } = await makeEncryptedPayload({
    v: 1,
    name: "demo",
    sharedSecret: "AQIDBAUGBwgJCgsMDQ4PEBESExQ="
  });
  const registered = await worker.fetch(
    new Request("https://example.com/api/register-link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload })
    }),
    {}
  );
  const link = await registered.json();
  const [id] = link.path.slice(1).split(".");

  assert.equal(registered.status, 200);

  const response = await worker.fetch(
    new Request("https://example.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, payload, key })
    }),
    {}
  );
  const text = await response.text();
  const body = JSON.parse(text);

  assert.equal(response.status, 200);
  assert.equal(body.name, "demo");
  assert.match(body.token, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
  assert.doesNotMatch(text, /AQIDBAUGBwgJCgsMDQ4PEBESExQ=/);
  assert.doesNotMatch(text, /sharedSecret/);
});

test("rejects expired encrypted payloads", async () => {
  const { payload, key } = await makeEncryptedPayload({
    v: 1,
    name: "demo",
    sharedSecret: "AQIDBAUGBwgJCgsMDQ4PEBESExQ=",
    expiresAt: Math.floor(Date.now() / 1000) - 1
  });
  const response = await worker.fetch(
    new Request("https://example.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: "0", payload, key })
    }),
    {}
  );

  assert.equal(response.status, 410);
});

test("registers and validates links with KV when LINK_KV is bound", async () => {
  const { payload, key } = await makeEncryptedPayload({
    v: 1,
    name: "kv-demo",
    sharedSecret: "AQIDBAUGBwgJCgsMDQ4PEBESExQ="
  });
  const env = { LINK_KV: makeKV() };
  const registered = await worker.fetch(
    new Request("https://example.com/api/register-link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload })
    }),
    env
  );
  const link = await registered.json();
  const [id] = link.path.slice(1).split(".");

  assert.equal(registered.status, 200);
  assert.equal(link.storage, "kv");
  assert.notEqual(id, "0");

  const response = await worker.fetch(
    new Request("https://example.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, payload, key })
    }),
    env
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.name, "kv-demo");
  assert.match(body.token, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
});

test("registers and validates links with D1 when LINK_DB is bound", async () => {
  const { payload, key } = await makeEncryptedPayload({
    v: 1,
    name: "d1-demo",
    sharedSecret: "AQIDBAUGBwgJCgsMDQ4PEBESExQ="
  });
  const env = { LINK_DB: makeD1() };
  const registered = await worker.fetch(
    new Request("https://example.com/api/register-link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload })
    }),
    env
  );
  const link = await registered.json();
  const [id] = link.path.slice(1).split(".");

  assert.equal(registered.status, 200);
  assert.equal(link.storage, "d1");
  assert.notEqual(id, "0");

  const response = await worker.fetch(
    new Request("https://example.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, payload, key })
    }),
    env
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.name, "d1-demo");
  assert.match(body.token, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
});

test("injects an optional background image from env", async () => {
  const response = await worker.fetch(new Request("https://example.com/"), {
    BACKGROUND_IMAGE_URL: "https://example.com/bg.jpg"
  });
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /url\("https:\/\/example.com\/bg.jpg"\)/);
});

test("requires password when ACCESS_PASSWORD is configured", async () => {
  const protectedEnv = {
    ACCESS_PASSWORD: "open-sesame",
    SESSION_SECRET: "unit-test-session-secret-with-enough-length"
  };

  const response = await worker.fetch(new Request("https://example.com/"), protectedEnv);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /访问密码/);
  assert.doesNotMatch(body, /secret-input/);
});

test("accepts authenticated page requests when ACCESS_PASSWORD is configured", async () => {
  const protectedEnv = {
    ACCESS_PASSWORD: "open-sesame",
    SESSION_SECRET: "unit-test-session-secret-with-enough-length"
  };

  const loginResponse = await worker.fetch(
    new Request("https://example.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "open-sesame" })
    }),
    protectedEnv
  );
  const cookie = loginResponse.headers.get("Set-Cookie");

  assert.equal(loginResponse.status, 200);
  assert.match(cookie, /sg_session=/);
  assert.match(cookie, /HttpOnly/);

  const pageResponse = await worker.fetch(
    new Request("https://example.com/", {
      headers: { Cookie: cookie }
    }),
    protectedEnv
  );
  const body = await pageResponse.text();

  assert.equal(pageResponse.status, 200);
  assert.match(body, /secret-input/);
});

async function makeEncryptedPayload(value) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt"
  ]);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(JSON.stringify(value))
    )
  );
  const packed = new Uint8Array(1 + iv.length + ciphertext.length);
  packed[0] = 1;
  packed.set(iv, 1);
  packed.set(ciphertext, 13);
  return {
    payload: base64UrlEncode(packed),
    key: base64UrlEncode(rawKey)
  };
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function makeKV() {
  const rows = new Map();
  return {
    async put(key, value) {
      rows.set(key, value);
    },
    async get(key, type) {
      const value = rows.get(key);
      if (!value) return null;
      return type === "json" ? JSON.parse(value) : value;
    },
    async delete(key) {
      rows.delete(key);
    }
  };
}

function makeD1() {
  const rows = new Map();
  return {
    async exec() {},
    prepare(sql) {
      return {
        params: [],
        bind(...params) {
          this.params = params;
          return this;
        },
        async run() {
          if (/insert or replace into links/i.test(sql)) {
            const [id, payloadHash, expiresAt, createdAt] = this.params;
            rows.set(id, {
              payload_hash: payloadHash,
              expires_at: expiresAt,
              created_at: createdAt
            });
          }
          if (/delete from links/i.test(sql)) {
            rows.delete(this.params[0]);
          }
          return { success: true };
        },
        async first() {
          if (/select payload_hash, expires_at from links/i.test(sql)) {
            return rows.get(this.params[0]) || null;
          }
          return null;
        }
      };
    }
  };
}
