export const EXPORT_VERSION = 1;

export function createEncryptedVaultExport({ username, kdf, entries, passwordProtected = false }) {
  return {
    app: "secure-password-manager",
    version: EXPORT_VERSION,
    exportedAt: new Date().toISOString(),
    username,
    kdf,
    passwordProtected,
    entries: entries.map((entry) => ({
      iv: entry.iv,
      ciphertext: entry.ciphertext
    }))
  };
}

export function stringifyEncryptedVaultExport(exportPayload) {
  return JSON.stringify(exportPayload, null, 2);
}

export function parseEncryptedVaultImport(input) {
  const payload = typeof input === "string" ? JSON.parse(input) : input;

  if (!payload || payload.app !== "secure-password-manager" || payload.version !== EXPORT_VERSION) {
    throw new Error("Неподдържан формат на файл.");
  }

  if (!Array.isArray(payload.entries)) {
    throw new Error("Файлът не съдържа списък със записи.");
  }

  for (const entry of payload.entries) {
    if (!entry || typeof entry.iv !== "string" || typeof entry.ciphertext !== "string") {
      throw new Error("Файлът съдържа невалиден криптиран запис.");
    }
  }

  return {
    app: payload.app,
    version: payload.version,
    exportedAt: payload.exportedAt,
    username: payload.username,
    kdf: payload.kdf,
    passwordProtected: Boolean(payload.passwordProtected),
    entries: payload.entries.map((entry) => ({
      iv: entry.iv,
      ciphertext: entry.ciphertext
    }))
  };
}

export function exportContainsPlaintext(exportPayload, sensitiveValues) {
  const serialized = JSON.stringify(exportPayload);
  return sensitiveValues.some((value) => value && serialized.includes(value));
}
