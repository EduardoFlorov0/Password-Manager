const API_URL = import.meta.env.VITE_API_URL || "http://localhost:4000";

async function request(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...options.headers
  };

  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }

  const response = await fetch(`${API_URL}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (response.status === 204) {
    return null;
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || "Заявката е неуспешна.");
    error.status = response.status;
    throw error;
  }

  return data;
}

export const api = {
  register(body) {
    return request("/api/users/register", { method: "POST", body });
  },
  getKdf(username) {
    return request(`/api/auth/kdf/${encodeURIComponent(username)}`);
  },
  login(body) {
    return request("/api/auth/login", { method: "POST", body });
  },
  listVault(token) {
    return request("/api/vault", { token });
  },
  createEntry(token, body) {
    return request("/api/vault", { method: "POST", token, body });
  },
  updateEntry(token, id, body) {
    return request(`/api/vault/${id}`, { method: "PUT", token, body });
  },
  deleteEntry(token, id) {
    return request(`/api/vault/${id}`, { method: "DELETE", token });
  },
  importVault(token, entries) {
    return request("/api/vault/import", { method: "POST", token, body: { entries } });
  }
};
