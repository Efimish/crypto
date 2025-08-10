import { expect, test } from "bun:test";
import { ed25519, x25519 } from "@noble/curves/ed25519";

test("ed25519 sign and verify", () => {
  const { secretKey, publicKey } = ed25519.keygen();
  const message = "Hello, World!";
  const bytes = new TextEncoder().encode(message);
  const signature = ed25519.sign(bytes, secretKey);
  expect(ed25519.verify(signature, bytes, publicKey)).toBe(true);
});

test("convert ed25519 to x25519", () => {
  const ed25519SecretKey = ed25519.utils.randomSecretKey();
  const ed25519PublicKey = ed25519.getPublicKey(ed25519SecretKey);

  const x25519SecretKey = ed25519.utils.toMontgomeryPriv(ed25519SecretKey);
  const x25519PublicKey = ed25519.utils.toMontgomery(ed25519PublicKey);

  expect(x25519.getPublicKey(x25519SecretKey)).toEqual(x25519PublicKey);
});

test("ed25519 signature length", () => {
  const secretKey = ed25519.utils.randomSecretKey();

  const messages = [
    "Hello, world!",
    "The quick brown fox jumps over the lazy dog",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
  ];

  expect(
    messages.every(
      (message) =>
        ed25519.sign(new TextEncoder().encode(message), secretKey).length === 64
    )
  ).toBe(true);
});

test("ed25519 sign public key and info", () => {
  const { secretKey, publicKey } = ed25519.keygen();

  const info = new TextEncoder().encode("owner:efim");

  const signature = ed25519.sign(info, secretKey);

  const payload = {
    publicKey,
    info,
    signature,
  };

  // receiver
  const isValid = ed25519.verify(
    payload.signature,
    payload.info,
    payload.publicKey
  );
  expect(isValid).toBe(true);

  const infoText = new TextDecoder().decode(payload.info);
  expect(infoText).toContain("owner:");
});
