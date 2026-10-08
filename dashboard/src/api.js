const API = import.meta.env.VITE_API_URL || "";

async function readResponse(res, path) {
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `${path} ${res.status}`);
  return body;
}

export async function getJson(path, token) {
  const res = await fetch(`${API}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  return readResponse(res, path);
}

export async function postJson(path, body, token) {
  const res = await fetch(`${API}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return readResponse(res, path);
}

export async function putJson(path, body, token) {
  const res = await fetch(`${API}${path}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return readResponse(res, path);
}

export async function getDemoAdminToken() {
  const res = await fetch(`${API}/v1/demo/token?role=SECURITY_ADMIN&subject=dashboard-admin`, { method: "POST" });
  return readResponse(res, "/v1/demo/token");
}
