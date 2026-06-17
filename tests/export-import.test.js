import { describe, expect, it } from "vitest";
import { createKdfSalt, decryptVaultEntry, deriveSecrets, encryptVaultEntry } from "../client/src/lib/crypto.js";
import {
  createEncryptedVaultExport,
  exportContainsPlaintext,
  parseEncryptedVaultImport,
  stringifyEncryptedVaultExport
} from "../client/src/lib/exportImport.js";

describe("encrypted vault export and import", () => {
  it("exports encrypted entries without plaintext fields", async () => {
    const salt = createKdfSalt();
    const secrets = await deriveSecrets("export file password", salt, 1000);
    const entry = {
      service: "Bank Demo",
      username: "demo@example.test",
      password: "BankPassword!42",
      notes: "Plain notes should not be exported."
    };
    const encrypted = await encryptVaultEntry(secrets.encryptionKey, entry);
    const payload = createEncryptedVaultExport({
      username: "demo",
      kdf: secrets.kdf,
      entries: [encrypted]
    });

    expect(exportContainsPlaintext(payload, Object.values(entry))).toBe(false);

    const parsed = parseEncryptedVaultImport(stringifyEncryptedVaultExport(payload));
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0]).toEqual(encrypted);
  });

  it("supports password-protected export files for import by another user", async () => {
    const fileSecrets = await deriveSecrets("File-Password-2026!", createKdfSalt(), 1000);
    const otherUserSecrets = await deriveSecrets("Other-User-Password-2026!", createKdfSalt(), 1000);
    const entry = {
      service: "Shared Demo",
      username: "shared@example.test",
      password: "SharedPassword!42",
      notes: "Encrypted with file password."
    };
    const encryptedForFile = await encryptVaultEntry(fileSecrets.encryptionKey, entry);
    const payload = createEncryptedVaultExport({
      username: "demo",
      kdf: fileSecrets.kdf,
      entries: [encryptedForFile],
      passwordProtected: true
    });
    const parsed = parseEncryptedVaultImport(stringifyEncryptedVaultExport(payload));

    expect(parsed.passwordProtected).toBe(true);
    await expect(decryptVaultEntry(fileSecrets.encryptionKey, parsed.entries[0])).resolves.toEqual(entry);
    await expect(decryptVaultEntry(otherUserSecrets.encryptionKey, parsed.entries[0])).rejects.toThrow();
    expect(exportContainsPlaintext(payload, Object.values(entry))).toBe(false);
  });

  it("rejects unsupported import payloads", () => {
    expect(() => parseEncryptedVaultImport({ app: "other", version: 1, entries: [] })).toThrow(
      "Неподдържан формат на файл."
    );
  });
});
