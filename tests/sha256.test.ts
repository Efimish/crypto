import { expect, test } from "bun:test";
import { sha256 } from "@noble/hashes/sha2";

test("SHA-256 hash length", () => {
  const messages = [
    "Hello, world!",
    "The quick brown fox jumps over the lazy dog",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
  ];

  expect(
    messages.every(
      (message) => sha256(new TextEncoder().encode(message)).length === 32
    )
  ).toBe(true);
});
