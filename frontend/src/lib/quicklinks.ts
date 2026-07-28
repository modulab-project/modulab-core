// API client for the quick-links / Schnellzugriff-Grid endpoints.
//
// Every call goes through lib/api.ts's request(). This file used to make its
// own fetch() calls instead, duplicating the credentials/error handling - and
// missing the one thing that duplicate did not replicate: csrfHeaders(). Once
// the admin guards began enforcing CSRF (2026-07-27), every admin quick-link
// mutation below started returning 403, with the UI only able to show the
// bare error text. Fixed 2026-07-28 by removing the second HTTP path
// entirely rather than adding the header to it, so the same class of drift
// cannot recur here.

import { request } from "./api";

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
// No token parameter on any function below: request() relies on the browser
// attaching the httpOnly __Host-modulab_session cookie automatically
// (credentials: "include") - see backend/internal/auth/handlers.go's
// setSessionCookie.

export function listQuickLinks(): Promise<Tile[]> {
  return request<Tile[]>("/v1/quick-links");
}

export async function createUserQuickLink(body: {
  title: string;
  url: string;
  icon: string;
  description: string;
}): Promise<Tile> {
  const { id } = await request<{ id: string }>("/v1/quick-links", {
    method: "POST",
    body: JSON.stringify(body),
  });
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

export function deleteUserQuickLink(id: string): Promise<void> {
  return request<void>(`/v1/quick-links/${id}`, { method: "DELETE" });
}

export function saveOrder(order: TileRef[]): Promise<void> {
  return request<void>("/v1/quick-links/order", {
    method: "PATCH",
    body: JSON.stringify({ order }),
  });
}

// ---- Admin endpoints --------------------------------------------------------

export function listAdminQuickLinks(): Promise<AdminTile[]> {
  return request<AdminTile[]>("/v1/admin/quick-links");
}

export function createAdminQuickLink(body: {
  title: string;
  url: string;
  icon: string;
  description: string;
  sort_order: number;
}): Promise<AdminTile> {
  return request<AdminTile>("/v1/admin/quick-links", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function updateAdminQuickLink(
  id: string,
  body: { title: string; url: string; icon: string; description: string; sort_order: number },
): Promise<void> {
  return request<void>(`/v1/admin/quick-links/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function deleteAdminQuickLink(id: string): Promise<void> {
  return request<void>(`/v1/admin/quick-links/${id}`, { method: "DELETE" });
}
