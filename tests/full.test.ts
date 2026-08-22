import { test, expect } from "vitest";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { generateMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/curves/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

test("full", () => {
  // two users entered their mnemonics with 24 words
  const mnemonicA = generateMnemonic(wordlist, 256);
  const mnemonicB = generateMnemonic(wordlist, 256);

  // their mnemonics are converted into secret keys ed25519
  const seedA = mnemonicToEntropy(mnemonicA, wordlist);
  const seedB = mnemonicToEntropy(mnemonicB, wordlist);
  const ed25519KeypairA = ed25519.keygen(seedA);
  const ed25519KeypairB = ed25519.keygen(seedB);

  // user A wants to send user B a message
  const x25519EphemeralKeypairA = x25519.keygen();
  const sharedSecretA = x25519.getSharedSecret(
    x25519EphemeralKeypairA.secretKey,
    ed25519.utils.toMontgomery(ed25519KeypairB.publicKey),
  );
  const messageTextA = "Hello, user B!";
  const messageBytesA = new TextEncoder().encode(messageTextA);
  const nonceA = randomBytes(24);
  const xchachaA = xchacha20poly1305(sharedSecretA, nonceA);
  const messageEncryptedA = xchachaA.encrypt(messageBytesA);

  const messageA = {
    publicKey: x25519EphemeralKeypairA.publicKey,
    nonce: nonceA,
    message: messageEncryptedA,
  };

  // the message was sent...
  const messageB = messageA;
  const sharedSecretB = x25519.getSharedSecret(
    ed25519.utils.toMontgomerySecret(ed25519KeypairB.secretKey),
    messageB.publicKey,
  );
  const nonceB = messageB.nonce;
  const messageEncryptedB = messageB.message;
  const xchachaB = xchacha20poly1305(sharedSecretB, nonceB);
  const messageBytesB = xchachaB.decrypt(messageEncryptedB);
  const messageTextB = new TextDecoder().decode(messageBytesB);

  // we got it
  expect(messageTextA).toBe(messageTextB);
});
