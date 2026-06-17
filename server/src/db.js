import initSqlJs from "sql.js";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dbPath = process.env.SQLITE_PATH || path.join(serverRoot, "data", "vault.db");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const require = createRequire(import.meta.url);
const sqlJsDir = path.dirname(require.resolve("sql.js/dist/sql-wasm.wasm"));
const SQL = await initSqlJs({
  locateFile: (file) => path.join(sqlJsDir, file)
});

const existingDatabase = fs.existsSync(dbPath) ? fs.readFileSync(dbPath) : null;
export const db = existingDatabase ? new SQL.Database(existingDatabase) : new SQL.Database();

function persistDatabase() {
  fs.writeFileSync(dbPath, Buffer.from(db.export()));
}

db.exec(`
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    kdf_algorithm TEXT NOT NULL,
    kdf_hash TEXT NOT NULL,
    kdf_iterations INTEGER NOT NULL,
    kdf_salt TEXT NOT NULL,
    auth_verifier TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    iv TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);
persistDatabase();

function run(sql, params = [], persist = true) {
  const statement = db.prepare(sql);

  try {
    statement.run(params);
    const changes = db.getRowsModified();
    const result = get("SELECT last_insert_rowid() AS lastInsertRowid", [], false) || {};
    const info = {
      changes,
      lastInsertRowid: result.lastInsertRowid
    };

    if (persist) {
      persistDatabase();
    }

    return info;
  } finally {
    statement.free();
  }
}

function get(sql, params = []) {
  const statement = db.prepare(sql);

  try {
    statement.bind(params);
    return statement.step() ? statement.getAsObject() : undefined;
  } finally {
    statement.free();
  }
}

function all(sql, params = []) {
  const statement = db.prepare(sql);
  const rows = [];

  try {
    statement.bind(params);
    while (statement.step()) {
      rows.push(statement.getAsObject());
    }
    return rows;
  } finally {
    statement.free();
  }
}

export function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

export function createUser({ username, kdf, authVerifier }) {
  const normalizedUsername = normalizeUsername(username);
  const info = run(
    `
    INSERT INTO users (
      username,
      kdf_algorithm,
      kdf_hash,
      kdf_iterations,
      kdf_salt,
      auth_verifier
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `,
    [normalizedUsername, kdf.algorithm, kdf.hash, kdf.iterations, kdf.salt, authVerifier]
  );

  return getUserById(info.lastInsertRowid);
}

export function getUserById(id) {
  return get("SELECT * FROM users WHERE id = ?", [id]);
}

export function getUserByUsername(username) {
  return get("SELECT * FROM users WHERE username = ?", [normalizeUsername(username)]);
}

export function serializeUserKdf(user) {
  return {
    algorithm: user.kdf_algorithm,
    hash: user.kdf_hash,
    iterations: user.kdf_iterations,
    salt: user.kdf_salt
  };
}

export function listEntries(userId) {
  return all(
    "SELECT id, iv, ciphertext, created_at AS createdAt, updated_at AS updatedAt FROM vault_entries WHERE user_id = ? ORDER BY updated_at DESC, id DESC",
    [userId]
  );
}

export function insertEntry(userId, { iv, ciphertext }) {
  const info = run("INSERT INTO vault_entries (user_id, iv, ciphertext) VALUES (?, ?, ?)", [userId, iv, ciphertext]);

  return get(
    "SELECT id, iv, ciphertext, created_at AS createdAt, updated_at AS updatedAt FROM vault_entries WHERE id = ? AND user_id = ?",
    [info.lastInsertRowid, userId]
  );
}

export function updateEntry(userId, entryId, { iv, ciphertext }) {
  const info = run(
    "UPDATE vault_entries SET iv = ?, ciphertext = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
    [iv, ciphertext, entryId, userId]
  );

  if (info.changes === 0) {
    return null;
  }

  return get(
    "SELECT id, iv, ciphertext, created_at AS createdAt, updated_at AS updatedAt FROM vault_entries WHERE id = ? AND user_id = ?",
    [entryId, userId]
  );
}

export function deleteEntry(userId, entryId) {
  return run("DELETE FROM vault_entries WHERE id = ? AND user_id = ?", [entryId, userId]).changes;
}

export function replaceEntries(userId, entries) {
  db.exec("BEGIN TRANSACTION");

  try {
    run("DELETE FROM vault_entries WHERE user_id = ?", [userId], false);

    for (const entry of entries) {
      run("INSERT INTO vault_entries (user_id, iv, ciphertext) VALUES (?, ?, ?)", [userId, entry.iv, entry.ciphertext], false);
    }

    db.exec("COMMIT");
    persistDatabase();
    return listEntries(userId);
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}
