// Dev-mode auth: the caller pastes an Ed25519-signed PrintForge JWT
// into a login form, we stash it in localStorage, and every API call
// attaches it as `Authorization: Bearer <token>`.
//
// A proper OIDC exchange (authorize → callback → exchange at
// /api/v1/auth/session) is the next slice. That endpoint does not yet
// exist on the gateway; once it does, this module switches to
// oidc-client-ts driving the authorize redirect, receiving the IdP
// code, and POSTing it to the gateway in return for a PrintForge JWT.

const TOKEN_KEY = 'pf_admin_token';

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

/// Best-effort decode of the JWT payload for display (name, roles). We
/// DO NOT verify the signature client-side — the gateway is the authority
/// on every request. This is purely cosmetic: show the caller who they
/// are logged in as.
export interface DecodedClaims {
  sub?: string;
  roles?: string[];
  exp?: number;
}

export function decodeClaims(token: string): DecodedClaims | null {
  try {
    const [, payload] = token.split('.');
    if (!payload) return null;
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    const json = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json) as DecodedClaims;
  } catch {
    return null;
  }
}
