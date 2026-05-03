import assert from "node:assert/strict";
import test from "node:test";

import worker from "../worker.js";

test("serves the app without any required secrets", async () => {
  const response = await worker.fetch(new Request("https://example.com/"), {});
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /Steam Guard Link/);
  assert.match(body, /\/密文#钥匙/);
  assert.doesNotMatch(body, /LINK_SECRET/);
});

test("serves shared-link routes without server-side decryption", async () => {
  const response = await worker.fetch(new Request("https://example.com/abcDEF_123"), {});
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
  const response = await worker.fetch(
    new Request("https://example.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload, key })
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
