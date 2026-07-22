// API client for the quick-links / Schnellzugriff-Grid endpoints.

const API = import.meta.env.VITE_API_BASE_URL ?? "";

// Tile is one entry in the merged list returned by GET /v1/quick-links.
export interface Tile {
  id: string;
  type: "admin" | "user";
  title: string;
  url: string;
  icon: string;
  description: string;
  sort_order: number;
}

// AdminTile is one entry returned by GET /v1/admin/quick-links.
export interface AdminTile {
  id: string;
  title: string;
  url: string;
  icon: string;
  description: string;
  sort_order: number;
  created_by: string;
}

export interface TileRef {
  type: "admin" | "user";
  id: string;
}

// ---- User endpoints ---------------------------------------------------------
// No token parameter on any function below: every request relies on the
// browser attaching the httpOnly __Host-modulab_session cookie automatically
// (credentials: "include"), same as lib/api.ts's request() wrapper - see
// backend/internal/auth/handlers.go's setSessionCookie.

export async function listQuickLinks(): Promise<Tile[]> {
  const res = await fetch(`${API}/v1/quick-links`, { credentials: "include" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function createUserQuickLink(
  body: { title: string; url: string; icon: string; description: string }
): Promise<Tile> {
  const res = await fetch(`${API}/v1/quick-links`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await res.text());
  const { id } = (await res.json()) as { id: string };
  // Return the tile immediately so the grid can append it optimistically.
  return {
    id,
    type: "user",
    title: body.title,
    url: body.url,
    icon: body.icon || "ti-link",
    description: body.description,
    sort_order: 0,
  };
}

export async function deleteUserQuickLink(id: string): Promise<void> {
  const res = await fetch(`${API}/v1/quick-links/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function saveOrder(order: TileRef[]): Promise<void> {
  const res = await fetch(`${API}/v1/quick-links/order`, {
    method: "PATCH",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ order }),
  });
  if (!res.ok) throw new Error(await res.text());
}

// ---- Admin endpoints --------------------------------------------------------

export async function listAdminQuickLinks(): Promise<AdminTile[]> {
  const res = await fetch(`${API}/v1/admin/quick-links`, { credentials: "include" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function createAdminQuickLink(
  body: { title: string; url: string; icon: string; description: string; sort_order: number }
): Promise<AdminTile> {
  const res = await fetch(`${API}/v1/admin/quick-links`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function updateAdminQuickLink(
  id: string,
  body: { title: string; url: string; icon: string; description: string; sort_order: number }
): Promise<void> {
  const res = await fetch(`${API}/v1/admin/quick-links/${id}`, {
    method: "PATCH",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function deleteAdminQuickLink(id: string): Promise<void> {
  const res = await fetch(`${API}/v1/admin/quick-links/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) throw new Error(await res.text());
}
