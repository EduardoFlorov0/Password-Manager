import { describe, expect, it } from "vitest";
import { createKdfSalt, decryptVaultEntry, deriveSecrets, encryptVaultEntry } from "../client/src/lib/crypto.js";

describe("client-side cryptography", () => {
  it("encrypts and decrypts an entry with AES-GCM", async () => {
    const salt = createKdfSalt();
    const secrets = await deriveSecrets("Correct Horse Battery Staple 2026!", salt, 1000);
    const entry = {
      service: "University Portal",
      username: "student@example.test",
      password: "S3cret!DiplomaValue",
      notes: "Defense demo account"
    };

    const encrypted = await encryptVaultEntry(secrets.encryptionKey, entry);
    const serialized = JSON.stringify(encrypted);

    expect(encrypted.iv).toBeTypeOf("string");
    expect(encrypted.ciphertext).toBeTypeOf("string");
    expect(serialized).not.toContain(entry.service);
    expect(serialized).not.toContain(entry.username);
    expect(serialized).not.toContain(entry.password);

    await expect(decryptVaultEntry(secrets.encryptionKey, encrypted)).resolves.toEqual(entry);
  });

  it("fails to decrypt with an incorrect profile password", async () => {
    const salt = createKdfSalt();
    const correct = await deriveSecrets("correct profile password", salt, 1000);
    const wrong = await deriveSecrets("wrong profile password", salt, 1000);
    const encrypted = await encryptVaultEntry(correct.encryptionKey, {
      service: "Email",
      username: "alice@example.test",
      password: "NeverPlaintext!",
      notes: ""
    });

    await expect(decryptVaultEntry(wrong.encryptionKey, encrypted)).rejects.toThrow();
  });

  it("derives different authentication verifiers for different passwords", async () => {
    const salt = createKdfSalt();
    const first = await deriveSecrets("profile password one", salt, 1000);
    const second = await deriveSecrets("profile password two", salt, 1000);

    expect(first.authVerifier).not.toEqual(second.authVerifier);
  });
});
