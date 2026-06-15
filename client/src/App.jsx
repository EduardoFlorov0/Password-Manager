import {
  Copy,
  Download,
  Edit3,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  LogIn,
  Save,
  Search,
  Trash2,
  Upload,
  UserPlus,
  X
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { createKdfSalt, decryptVaultEntry, deriveSecrets, encryptVaultEntry } from "./lib/crypto.js";
import {
  createEncryptedVaultExport,
  parseEncryptedVaultImport,
  stringifyEncryptedVaultExport
} from "./lib/exportImport.js";
import { generatePassword } from "./lib/passwordGenerator.js";

const AUTO_LOCK_MS = 5 * 60 * 1000;

const emptyEntry = {
  service: "",
  username: "",
  password: "",
  notes: ""
};

const requiredFieldProps = {
  onInvalid: (event) => {
    event.currentTarget.setCustomValidity("Моля, попълнете това поле.");
  },
  onInput: (event) => {
    event.currentTarget.setCustomValidity("");
  }
};

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

function getRegistrationPasswordError(password) {
  const meetsRequirements =
    password.length >= 10 &&
    /\p{Lu}/u.test(password) &&
    /\p{Ll}/u.test(password) &&
    /[^\p{L}\p{N}\s]/u.test(password);

  return meetsRequirements ? "" : "Паролата трябва да съдържа поне 10 символа, главна буква, малка буква и специален символ.";
}

function formatRecordCount(count) {
  if (count === 1) {
    return "1 запазена парола";
  }
  return `${count} запазени пароли`;
}

function getEmptyStateText(totalEntries, searchQuery) {
  if (totalEntries > 0 && searchQuery.trim()) {
    return "Няма резултати за търсенето.";
  }
  return "Няма запазени пароли.";
}

export default function App() {
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({ username: "", masterPassword: "" });
  const [session, setSession] = useState(null);
  const [entries, setEntries] = useState([]);
  const [encryptedEntries, setEncryptedEntries] = useState([]);
  const [entryForm, setEntryForm] = useState(emptyEntry);
  const [editingId, setEditingId] = useState(null);
  const [search, setSearch] = useState("");
  const [generator, setGenerator] = useState({
    length: 18,
    uppercase: true,
    lowercase: true,
    digits: true,
    special: true
  });
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState("");
  const [passwordDialog, setPasswordDialog] = useState(null);
  const [passwordDialogValue, setPasswordDialogValue] = useState("");
  const [busy, setBusy] = useState(false);
  const importInputRef = useRef(null);
  const passwordDialogResolverRef = useRef(null);

  const hasDraftEntry = Object.values(entryForm).some((value) => String(value || "").trim().length > 0);

  const filteredEntries = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) {
      return entries;
    }

    return entries.filter((entry) =>
      [entry.service, entry.username, entry.notes].some((value) => String(value || "").toLowerCase().includes(query))
    );
  }, [entries, search]);
  const registrationPasswordError =
    authMode === "register" && authForm.masterPassword ? getRegistrationPasswordError(authForm.masterPassword) : "";

  const lockSession = useCallback(() => {
    const resolvePasswordDialog = passwordDialogResolverRef.current;
    passwordDialogResolverRef.current = null;
    setSession(null);
    setEntries([]);
    setEncryptedEntries([]);
    setEditingId(null);
    setEntryForm(emptyEntry);
    setShowPassword(false);
    setPasswordDialog(null);
    setPasswordDialogValue("");
    setAuthError("");
    resolvePasswordDialog?.("");
  }, []);

  useEffect(() => {
    if (!session) {
      return undefined;
    }

    let timerId;
    const resetTimer = () => {
      window.clearTimeout(timerId);
      timerId = window.setTimeout(() => lockSession(), AUTO_LOCK_MS);
    };
    const events = ["click", "keydown", "mousemove", "scroll", "touchstart"];

    events.forEach((eventName) => window.addEventListener(eventName, resetTimer, { passive: true }));
    resetTimer();

    return () => {
      window.clearTimeout(timerId);
      events.forEach((eventName) => window.removeEventListener(eventName, resetTimer));
    };
  }, [lockSession, session]);

  async function loadVault(token, encryptionKey) {
    const data = await api.listVault(token);
    const decryptedEntries = [];

    for (const encryptedEntry of data.entries) {
      const decrypted = await decryptVaultEntry(encryptionKey, encryptedEntry);
      decryptedEntries.push({
        id: encryptedEntry.id,
        createdAt: encryptedEntry.createdAt,
        updatedAt: encryptedEntry.updatedAt,
        ...decrypted
      });
    }

    setEncryptedEntries(data.entries);
    setEntries(decryptedEntries);
  }

  async function handleAuthSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setAuthError("");

    const username = normalizeUsername(authForm.username);
    const masterPassword = authForm.masterPassword;

    try {
      if (authMode === "register") {
        const passwordError = getRegistrationPasswordError(masterPassword);
        if (passwordError) {
          return;
        }

        const salt = createKdfSalt();
        const secrets = await deriveSecrets(masterPassword, salt);
        const result = await api.register({
          username,
          kdf: secrets.kdf,
          authVerifier: secrets.authVerifier
        });

        setSession({
          token: result.token,
          username: result.user.username,
          kdf: result.kdf,
          encryptionKey: secrets.encryptionKey
        });
        setAuthForm({ username, masterPassword: "" });
        await loadVault(result.token, secrets.encryptionKey);
        return;
      }

      const bootstrap = await api.getKdf(username);
      const secrets = await deriveSecrets(masterPassword, bootstrap.kdf.salt, bootstrap.kdf.iterations);
      const result = await api.login({ username, authKey: secrets.authKeyB64 });

      setSession({
        token: result.token,
        username: result.user.username,
        kdf: result.kdf,
        encryptionKey: secrets.encryptionKey
      });
      setAuthForm({ username, masterPassword: "" });
      await loadVault(result.token, secrets.encryptionKey);
    } catch (error) {
      if (authMode === "login" && [401, 404].includes(error.status)) {
        setAuthError("Грешен потребител или парола.");
      } else {
        setAuthError(error.message);
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveEntry(event) {
    event.preventDefault();
    if (!session) {
      return;
    }

    setBusy(true);
    setAuthError("");

    try {
      const encrypted = await encryptVaultEntry(session.encryptionKey, {
        service: entryForm.service.trim(),
        username: entryForm.username.trim(),
        password: entryForm.password,
        notes: entryForm.notes.trim()
      });

      if (editingId) {
        await api.updateEntry(session.token, editingId, encrypted);
      } else {
        await api.createEntry(session.token, encrypted);
      }

      setEntryForm(emptyEntry);
      setEditingId(null);
      await loadVault(session.token, session.encryptionKey);
      setAuthError("");
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setBusy(false);
    }
  }

  function handleEdit(entry) {
    setEditingId(entry.id);
    setEntryForm({
      service: entry.service,
      username: entry.username,
      password: entry.password,
      notes: entry.notes || ""
    });
  }

  function handleClearEntryForm() {
    setEditingId(null);
    setEntryForm(emptyEntry);
    setShowPassword(false);
  }

  async function handleDelete(id) {
    if (!session) {
      return;
    }

    setBusy(true);
    setAuthError("");

    try {
      await api.deleteEntry(session.token, id);
      if (editingId === id) {
        setEditingId(null);
        setEntryForm(emptyEntry);
      }
      await loadVault(session.token, session.encryptionKey);
      setAuthError("");
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setBusy(false);
    }
  }

  function handleGeneratePassword() {
    try {
      const password = generatePassword(generator);
      setEntryForm((current) => ({ ...current, password }));
      setShowPassword(true);
      setAuthError("");
    } catch (error) {
      setAuthError(error.message);
    }
  }

  async function handleCopyPassword(password) {
    try {
      await navigator.clipboard.writeText(password);
      setAuthError("");
    } catch {
      setAuthError("Клипбордът не е достъпен.");
    }
  }

  async function decryptEntriesWithKey(encryptionKey, entriesToDecrypt) {
    const decryptedEntries = [];
    for (const encryptedEntry of entriesToDecrypt) {
      decryptedEntries.push(await decryptVaultEntry(encryptionKey, encryptedEntry));
    }
    return decryptedEntries;
  }

  async function encryptEntriesWithKey(encryptionKey, entriesToEncrypt) {
    const encrypted = [];
    for (const entry of entriesToEncrypt) {
      encrypted.push(await encryptVaultEntry(encryptionKey, entry));
    }
    return encrypted;
  }

  function requestHiddenPassword({ title, submitLabel }) {
    setPasswordDialog({ title, submitLabel });
    setPasswordDialogValue("");

    return new Promise((resolve) => {
      passwordDialogResolverRef.current = resolve;
    });
  }

  function closePasswordDialog(value = "") {
    const resolve = passwordDialogResolverRef.current;
    passwordDialogResolverRef.current = null;
    setPasswordDialog(null);
    setPasswordDialogValue("");
    resolve?.(value);
  }

  function handlePasswordDialogSubmit(event) {
    event.preventDefault();
    closePasswordDialog(passwordDialogValue);
  }

  async function handleExport() {
    if (!session) {
      return;
    }

    const exportPassword = await requestHiddenPassword({
      title: "Парола за файла за експортиране",
      submitLabel: "Продължи"
    });
    if (!exportPassword) {
      return;
    }

    const passwordError = getRegistrationPasswordError(exportPassword);
    if (passwordError) {
      setAuthError(`Паролата за файла за експортиране не е достатъчно сигурна. ${passwordError}`);
      return;
    }

    setBusy(true);
    setAuthError("");

    try {
      const exportSecrets = await deriveSecrets(exportPassword, createKdfSalt());
      const decryptedEntries = await decryptEntriesWithKey(session.encryptionKey, encryptedEntries);
      const exportEntries = await encryptEntriesWithKey(exportSecrets.encryptionKey, decryptedEntries);

      const payload = createEncryptedVaultExport({
        username: session.username,
        kdf: exportSecrets.kdf,
        entries: exportEntries,
        passwordProtected: true
      });
      const blob = new Blob([stringifyEncryptedVaultExport(payload)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = `${session.username}-encrypted-passwords.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setAuthError("");
    } catch (error) {
      setAuthError(error.message ? `Експортирането е неуспешно: ${error.message}` : "Експортирането е неуспешно.");
    } finally {
      setBusy(false);
    }
  }

  async function handleImportFile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !session) {
      return;
    }

    setBusy(true);
    setAuthError("");

    try {
      const text = await file.text();
      const parsed = parseEncryptedVaultImport(text);
      let entriesForCurrentUser = parsed.entries;

      if (parsed.passwordProtected) {
        if (!parsed.kdf?.salt || !Number.isInteger(parsed.kdf.iterations)) {
          throw new Error("Файлът няма валидни данни за декриптиране.");
        }

        const importPassword = await requestHiddenPassword({
          title: "Парола за файла за импортиране",
          submitLabel: "Продължи"
        });
        if (!importPassword) {
          return;
        }

        const importSecrets = await deriveSecrets(importPassword, parsed.kdf.salt, parsed.kdf.iterations);
        try {
          const decryptedEntries = await decryptEntriesWithKey(importSecrets.encryptionKey, parsed.entries);
          entriesForCurrentUser = await encryptEntriesWithKey(session.encryptionKey, decryptedEntries);
        } catch {
          throw new Error("Грешна парола за файла за импортиране.");
        }
      } else {
        try {
          await decryptEntriesWithKey(session.encryptionKey, parsed.entries);
        } catch {
          throw new Error("Файлът е криптиран за друг потребител. Експортирайте го с парола за файла.");
        }
      }

      await api.importVault(session.token, entriesForCurrentUser);
      await loadVault(session.token, session.encryptionKey);
      setAuthError("");
    } catch (error) {
      setAuthError(error.message ? `Импортирането е неуспешно: ${error.message}` : "Импортирането е неуспешно.");
    } finally {
      setBusy(false);
    }
  }

  if (!session) {
    return (
      <main className="auth-shell">
        <section className="auth-panel">
          <div className="brand">
            <KeyRound aria-hidden="true" />
            <div>
              <h1>Мениджър на пароли</h1>
            </div>
          </div>

          <div className="mode-switch" role="tablist" aria-label="Режим за вход">
            <button
              type="button"
              className={authMode === "login" ? "active" : ""}
              onClick={() => {
                setAuthMode("login");
                setAuthError("");
              }}
            >
              <LogIn size={16} aria-hidden="true" />
              Вход
            </button>
            <button
              type="button"
              className={authMode === "register" ? "active" : ""}
              onClick={() => {
                setAuthMode("register");
                setAuthError("");
              }}
            >
              <UserPlus size={16} aria-hidden="true" />
              Регистрация
            </button>
          </div>

          <form className="auth-form" onSubmit={handleAuthSubmit}>
            <label>
              <span>Потребител</span>
              <input
                value={authForm.username}
                onChange={(event) => {
                  setAuthError("");
                  setAuthForm((current) => ({ ...current, username: event.target.value }));
                }}
                minLength={3}
                maxLength={40}
                autoComplete="username"
                required
                {...requiredFieldProps}
              />
            </label>
            <label>
              <span>Парола</span>
              <input
                value={authForm.masterPassword}
                onChange={(event) => {
                  setAuthError("");
                  setAuthForm((current) => ({ ...current, masterPassword: event.target.value }));
                }}
                type="password"
                autoComplete={authMode === "register" ? "new-password" : "current-password"}
                required
                {...requiredFieldProps}
              />
              {registrationPasswordError ? (
                <span className="field-hint error" aria-live="polite">
                  {registrationPasswordError}
                </span>
              ) : null}
            </label>

            {authError ? <p className="message error" aria-live="polite">{authError}</p> : null}

            <button className="primary-button" type="submit" disabled={busy}>
              {authMode === "login" ? <LogIn size={18} aria-hidden="true" /> : <UserPlus size={18} aria-hidden="true" />}
              {busy ? "Обработка..." : authMode === "login" ? "Вход" : "Създай профил"}
            </button>
          </form>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand compact">
          <KeyRound aria-hidden="true" />
          <div>
            <h1>Мениджър на пароли</h1>
            <p>{session.username}</p>
          </div>
        </div>
        <div className="topbar-actions">
          <button type="button" className="icon-text-button" onClick={handleExport}>
            <Download size={16} aria-hidden="true" />
            Експортирай
          </button>
          <button type="button" className="icon-text-button" onClick={() => importInputRef.current?.click()}>
            <Upload size={16} aria-hidden="true" />
            Импортирай
          </button>
          <button type="button" className="icon-text-button danger" onClick={() => lockSession()}>
            <Lock size={16} aria-hidden="true" />
            Изход
          </button>
          <input ref={importInputRef} className="hidden-input" type="file" accept="application/json" onChange={handleImportFile} />
        </div>
      </header>

      <section className="workspace">
        <aside className="editor-panel">
          <div className="panel-heading">
            <h2>{editingId ? "Редактиране на запис" : "Нов запис"}</h2>
            {editingId ? (
              <button
                type="button"
                className="icon-button"
                title="Откажи редакцията"
                onClick={handleClearEntryForm}
              >
                <X size={18} aria-hidden="true" />
              </button>
            ) : null}
          </div>

          <form className="entry-form" onSubmit={handleSaveEntry}>
            <label>
              <span>Услуга</span>
              <input
                value={entryForm.service}
                onChange={(event) => setEntryForm((current) => ({ ...current, service: event.target.value }))}
                required
                {...requiredFieldProps}
              />
            </label>
            <label>
              <span>Потребител</span>
              <input
                value={entryForm.username}
                onChange={(event) => setEntryForm((current) => ({ ...current, username: event.target.value }))}
                required
                {...requiredFieldProps}
              />
            </label>
            <label>
              <span>Парола</span>
              <div className="password-row">
                <input
                  value={entryForm.password}
                  onChange={(event) => setEntryForm((current) => ({ ...current, password: event.target.value }))}
                  type={showPassword ? "text" : "password"}
                  required
                  {...requiredFieldProps}
                />
                <button
                  type="button"
                  className="icon-button"
                  title={showPassword ? "Скрий паролата" : "Покажи паролата"}
                  onClick={() => setShowPassword((value) => !value)}
                >
                  {showPassword ? <EyeOff size={18} aria-hidden="true" /> : <Eye size={18} aria-hidden="true" />}
                </button>
              </div>
            </label>
            <label>
              <span>Бележки</span>
              <textarea
                value={entryForm.notes}
                onChange={(event) => setEntryForm((current) => ({ ...current, notes: event.target.value }))}
                rows={4}
              />
            </label>

            <div className="generator-panel">
              <div className="generator-row">
                <label>
                  <span>Дължина</span>
                  <input
                    type="number"
                    min={8}
                    max={128}
                    value={generator.length}
                    onChange={(event) => {
                      const nextLength = Math.max(8, Math.min(128, Number(event.target.value) || 8));
                      setGenerator((current) => ({ ...current, length: nextLength }));
                    }}
                  />
                </label>
                <button type="button" className="icon-text-button" onClick={handleGeneratePassword} title="Генерирай парола">
                  <KeyRound size={16} aria-hidden="true" />
                  Генерирай
                </button>
              </div>
              <div className="check-grid">
                {[
                  ["uppercase", "ABC"],
                  ["lowercase", "abc"],
                  ["digits", "123"],
                  ["special", "#$!"]
                ].map(([key, label]) => (
                  <label key={key} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={generator[key]}
                      onChange={(event) => setGenerator((current) => ({ ...current, [key]: event.target.checked }))}
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="form-actions">
              <button className="secondary-button" type="button" disabled={busy || !hasDraftEntry} onClick={handleClearEntryForm}>
                <X size={18} aria-hidden="true" />
                Изчисти
              </button>
              <button className="primary-button" type="submit" disabled={busy}>
                <Save size={18} aria-hidden="true" />
                Запази
              </button>
            </div>
          </form>
        </aside>

        <section className="vault-panel">
          <div className="vault-toolbar">
            <div>
              <h2>Запазени пароли</h2>
              <p>{formatRecordCount(entries.length)}</p>
            </div>
            <label className="search-box">
              <Search size={17} aria-hidden="true" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Търсене в запазените пароли"
              />
            </label>
          </div>

          {authError ? <p className="message error" aria-live="polite">{authError}</p> : null}

          <div className="entry-list">
            {filteredEntries.length === 0 ? (
              <div className="empty-state">
                <KeyRound aria-hidden="true" />
                <p>{getEmptyStateText(entries.length, search)}</p>
              </div>
            ) : (
              filteredEntries.map((entry) => (
                <article key={entry.id} className="entry-card">
                  <div className="entry-main">
                    <div>
                      <h3>{entry.service}</h3>
                      <p>{entry.username}</p>
                    </div>
                    <div className="entry-actions">
                      <button
                        type="button"
                        className="icon-button"
                        title="Копирай паролата"
                        onClick={() => handleCopyPassword(entry.password)}
                      >
                        <Copy size={17} aria-hidden="true" />
                      </button>
                      <button type="button" className="icon-button" title="Редактирай записа" onClick={() => handleEdit(entry)}>
                        <Edit3 size={17} aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        className="icon-button danger"
                        title="Изтрий записа"
                        onClick={() => handleDelete(entry.id)}
                      >
                        <Trash2 size={17} aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                  <input className="concealed-password" value={entry.password} type="password" readOnly />
                  {entry.notes ? <p className="notes">{entry.notes}</p> : null}
                </article>
              ))
            )}
          </div>
        </section>
      </section>
      {passwordDialog ? (
        <div className="dialog-backdrop" role="presentation">
          <form className="password-dialog" onSubmit={handlePasswordDialogSubmit}>
            <h2>{passwordDialog.title}</h2>
            <input
              autoFocus
              value={passwordDialogValue}
              onChange={(event) => setPasswordDialogValue(event.target.value)}
              type="password"
              required
            />
            <div className="dialog-actions">
              <button type="button" className="secondary-button" onClick={() => closePasswordDialog("")}>
                Отказ
              </button>
              <button type="submit" className="primary-button">
                {passwordDialog.submitLabel}
              </button>
            </div>
          </form>
        </div>
      ) : null}
    </main>
  );
}
