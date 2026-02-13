import { test, expect } from "vitest";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { generateMnemonic, entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { ed25519 } from "@noble/curves/ed25519.js";

test("generate seed phrase with 24 words", () => {
  // 24 words / 32 bytes
  const seed = generateMnemonic(wordlist, 256);
  const words = seed.split(" ");
  expect(words.length).toBe(24);
});

test("private key to seed phrase and back", () => {
  // 32 bytes
  const privateKey = ed25519.utils.randomSecretKey();
  // 24 words
  const seed = entropyToMnemonic(privateKey, wordlist);
  expect(seed.split(" ").length).toBe(24);

  const newPrivateKey = mnemonicToEntropy(seed, wordlist);
  expect(newPrivateKey).toStrictEqual(privateKey);
});
