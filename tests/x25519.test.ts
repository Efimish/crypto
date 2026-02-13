import { expect, test } from "bun:test";
import { x25519 } from "@noble/curves/ed25519.js";

test("x25519 static + static key exchange", () => {
  const keypairA = x25519.keygen();
  const keypairB = x25519.keygen();
  const sharedSecretA = x25519.getSharedSecret(
    keypairA.secretKey,
    keypairB.publicKey
  );
  const sharedSecretB = x25519.getSharedSecret(
    keypairB.secretKey,
    keypairA.publicKey
  );
  expect(sharedSecretA).toEqual(sharedSecretB);
});

test("x25519 static + ephemeral key exchange", () => {
  const keypairStatic = x25519.keygen();

  const { sharedSecretEphemeral, publicKeyEphemeral } = (() => {
    const keypairEphemeral = x25519.keygen();
    const sharedSecret = x25519.getSharedSecret(
      keypairEphemeral.secretKey,
      keypairStatic.publicKey
    );
    return {
      sharedSecretEphemeral: sharedSecret,
      publicKeyEphemeral: keypairEphemeral.publicKey,
    };
  })();

  const sharedSecretStatic = x25519.getSharedSecret(
    keypairStatic.secretKey,
    publicKeyEphemeral
  );

  expect(sharedSecretStatic).toEqual(sharedSecretEphemeral);
});
