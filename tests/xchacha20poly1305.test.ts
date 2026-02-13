import { test, expect } from "vitest";
import { randomBytes } from "@noble/curves/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

test("XChaCha20-Poly1305 encrypt and decrypt", () => {
  const key = randomBytes(32);
  const nonce = randomBytes(24);
  const xchacha = xchacha20poly1305(key, nonce);
  const message = "Hello, World!";
  const bytes = new TextEncoder().encode(message);
  const encrypted = xchacha.encrypt(bytes);
  const decryptedBytes = xchacha.decrypt(encrypted);
  const decrypted = new TextDecoder().decode(decryptedBytes);
  expect(decrypted).toBe(message);
});
