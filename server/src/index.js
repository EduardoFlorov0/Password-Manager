import cors from "cors";
import express from "express";
import {
  createUser,
  deleteEntry,
  getUserById,
  getUserByUsername,
  insertEntry,
  listEntries,
  normalizeUsername,
  replaceEntries,
  serializeUserKdf,
  updateEntry
} from "./db.js";
import { createToken, hashAuthKey, safeEqualBase64, verifyToken } from "./auth.js";

const app = express();
const port = Number(process.env.PORT || 4000);
const clientOrigin = process.env.CLIENT_ORIGIN || "http://localhost:5173";

app.use(cors({ origin: clientOrigin, credentials: false }));
app.use(express.json({ limit: "1mb" }));

function isValidUsername(username) {
  return /^[a-zA-Z0-9._-]{3,40}$/.test(String(username || ""));
}

function looksBase64(value) {
  return typeof value === "string" && value.length > 0 && /^[A-Za-z0-9+/=]+$/.test(value);
}

function requireAuth(req, res, next) {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({ error: "Изисква се автентикация." });
  }

  const user = getUserById(payload.sub);
  if (!user) {
    return res.status(401).json({ error: "Изисква се автентикация." });
  }

  req.user = user;
  return next();
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/users/register", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const { kdf, authVerifier } = req.body;

  if (!isValidUsername(username)) {
    return res.status(400).json({ error: "Потребителят трябва да е 3-40 символа и да съдържа букви, цифри, точка, тире или долна черта." });
  }

  if (
    !kdf ||
    kdf.algorithm !== "PBKDF2" ||
    kdf.hash !== "SHA-256" ||
    !Number.isInteger(kdf.iterations) ||
    kdf.iterations < 100000 ||
    !looksBase64(kdf.salt) ||
    !looksBase64(authVerifier)
  ) {
    return res.status(400).json({ error: "Невалидни регистрационни данни." });
  }

  if (getUserByUsername(username)) {
    return res.status(409).json({ error: "Потребителят вече съществува." });
  }

  const user = createUser({ username, kdf, authVerifier });
  res.status(201).json({
    token: createToken(user),
    user: { username: user.username },
    kdf: serializeUserKdf(user)
  });
});

app.get("/api/auth/kdf/:username", (req, res) => {
  const user = getUserByUsername(req.params.username);

  if (!user) {
    return res.status(404).json({ error: "Потребителят не е намерен." });
  }

  res.json({
    username: user.username,
    kdf: serializeUserKdf(user)
  });
});

app.post("/api/auth/login", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const { authKey } = req.body;
  const user = getUserByUsername(username);

  if (!user || !looksBase64(authKey)) {
    return res.status(401).json({ error: "Грешен потребител или парола." });
  }

  const verifier = hashAuthKey(authKey);
  if (!safeEqualBase64(verifier, user.auth_verifier)) {
    return res.status(401).json({ error: "Грешен потребител или парола." });
  }

  res.json({
    token: createToken(user),
    user: { username: user.username },
    kdf: serializeUserKdf(user)
  });
});

app.get("/api/vault", requireAuth, (req, res) => {
  res.json({ entries: listEntries(req.user.id) });
});

app.post("/api/vault", requireAuth, (req, res) => {
  const { iv, ciphertext } = req.body;

  if (!looksBase64(iv) || !looksBase64(ciphertext)) {
    return res.status(400).json({ error: "Криптираният запис трябва да съдържа base64 IV и ciphertext." });
  }

  res.status(201).json({ entry: insertEntry(req.user.id, { iv, ciphertext }) });
});

app.put("/api/vault/:id", requireAuth, (req, res) => {
  const { iv, ciphertext } = req.body;
  const entryId = Number(req.params.id);

  if (!Number.isInteger(entryId) || !looksBase64(iv) || !looksBase64(ciphertext)) {
    return res.status(400).json({ error: "Невалидно обновяване на криптиран запис." });
  }

  const entry = updateEntry(req.user.id, entryId, { iv, ciphertext });
  if (!entry) {
    return res.status(404).json({ error: "Записът не е намерен." });
  }

  res.json({ entry });
});

app.delete("/api/vault/:id", requireAuth, (req, res) => {
  const entryId = Number(req.params.id);

  if (!Number.isInteger(entryId)) {
    return res.status(400).json({ error: "Невалиден идентификатор на запис." });
  }

  const deleted = deleteEntry(req.user.id, entryId);
  if (!deleted) {
    return res.status(404).json({ error: "Записът не е намерен." });
  }

  res.status(204).end();
});

app.post("/api/vault/import", requireAuth, (req, res) => {
  const { entries } = req.body;

  if (
    !Array.isArray(entries) ||
    entries.length > 1000 ||
    entries.some((entry) => !looksBase64(entry.iv) || !looksBase64(entry.ciphertext))
  ) {
    return res.status(400).json({ error: "Импортът трябва да съдържа само криптирани записи." });
  }

  res.json({ entries: replaceEntries(req.user.id, entries) });
});

app.use((err, _req, res, _next) => {
  if (err && (err.code === "SQLITE_CONSTRAINT_UNIQUE" || String(err.message).includes("UNIQUE constraint failed"))) {
    return res.status(409).json({ error: "Потребителят вече съществува." });
  }

  res.status(500).json({ error: "Сървърна грешка." });
});

app.listen(port, () => {
  console.log(`Secure password manager API listening on http://localhost:${port}`);
});
