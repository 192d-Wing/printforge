# PrintForge Admin Web

React + Vite + TypeScript SPA for the `PrintForge` admin dashboard.

## Develop

```bash
npm install
VITE_API_TARGET=http://localhost:8443 npm run dev
```

The dev server listens on `:5173` and proxies `/api` + `/enroll` to the
gateway at `VITE_API_TARGET` (defaults to `http://localhost:8443`).

## Auth (dev mode)

The SPA expects a `PrintForge` Ed25519 JWT in `localStorage` under the
`pf_admin_token` key. In dev, sign in by pasting a token into `/login` —
the gateway remains the authority for every request.

A proper OIDC exchange is a planned follow-up: the SPA will run the
authorize dance with Entra ID / E-ICAM, receive the IdP ID token, and
POST it to `/api/v1/auth/session` (endpoint yet to land on the gateway)
in return for a `PrintForge` JWT.

## Build

```bash
npm run build
```

Output in `dist/` — deploy to a CDN. The gateway is a separate service
on its own domain; configure its `cors.allowed_origins` with the SPA's
origin.

## Pages

| Route | Backing endpoint |
|---|---|
| `/` | `GET /api/v1/admin/dashboard/kpis` |
| `/fleet` | `GET /api/v1/admin/fleet/overview` + `/fleet/printers` |
| `/jobs` | `GET /api/v1/admin/jobs` |
| `/users` | `GET /api/v1/admin/users` |
| `/users/:edipi` | `GET /api/v1/admin/users/{edipi}/quota` |
| `/alerts` | `GET /api/v1/admin/alerts` + `POST .../acknowledge` |
| `/reports` | `POST /api/v1/admin/reports/generate` |
| `/reports/:id` | `GET /api/v1/admin/reports/{id}` |
