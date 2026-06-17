export const DEFAULT_KDF = {
  algorithm: "PBKDF2",
  hash: "SHA-256",
  iterations: 250000,
  saltBytes: 16,
  derivedBits: 512
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function getWebCrypto() {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.subtle || !cryptoApi?.getRandomValues) {
    throw new Error("Web Crypto API не е достъпен.");
  }
  return cryptoApi;
}

export function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }

  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(base64) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  getWebCrypto().getRandomValues(bytes);
  return bytes;
}

export function createKdfSalt() {
  return bytesToBase64(randomBytes(DEFAULT_KDF.saltBytes));
}

export async function sha256Base64(bytes) {
  const digest = await getWebCrypto().subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(digest));
}

export async function deriveSecrets(masterPassword, saltBase64, iterations = DEFAULT_KDF.iterations) {
  if (!masterPassword) {
    throw new Error("Паролата е задължителна.");
  }

  const cryptoApi = getWebCrypto();
  const keyMaterial = await cryptoApi.subtle.importKey(
    "raw",
    textEncoder.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derived = await cryptoApi.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: base64ToBytes(saltBase64),
      iterations,
      hash: DEFAULT_KDF.hash
    },
    keyMaterial,
    DEFAULT_KDF.derivedBits
  );

  const derivedBytes = new Uint8Array(derived);
  const encryptionKeyBytes = derivedBytes.slice(0, 32);
  const authKeyBytes = derivedBytes.slice(32, 64);
  const encryptionKey = await cryptoApi.subtle.importKey(
    "raw",
    encryptionKeyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  return {
    encryptionKey,
    authKeyB64: bytesToBase64(authKeyBytes),
    authVerifier: await sha256Base64(authKeyBytes),
    kdf: {
      algorithm: DEFAULT_KDF.algorithm,
      hash: DEFAULT_KDF.hash,
      iterations,
      salt: saltBase64
    }
  };
}

export async function encryptVaultEntry(encryptionKey, entry) {
  const iv = randomBytes(12);
  const payload = {
    service: entry.service,
    username: entry.username,
    password: entry.password,
    notes: entry.notes || ""
  };

  if (entry.icon) {
    payload.icon = entry.icon;
  }

  const plaintext = textEncoder.encode(JSON.stringify(payload));

  const ciphertext = await getWebCrypto().subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    encryptionKey,
    plaintext
  );

  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

export async function decryptVaultEntry(encryptionKey, encryptedEntry) {
  const plaintext = await getWebCrypto().subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(encryptedEntry.iv)
    },
    encryptionKey,
    base64ToBytes(encryptedEntry.ciphertext)
  );

  return JSON.parse(textDecoder.decode(plaintext));
}
