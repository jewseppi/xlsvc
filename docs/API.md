# API base and routes (frontend <-> backend)

API base alignment and the "double api" (subdomain + path).

---

## Current state (aligned)

| Environment | Frontend base (`xlsvc-frontend/src/apiBase.js`) | Backend routes (`xlsvc/main.py`) | Resulting URL |
|-------------|--------------------------------------------------|----------------------------------|----------------|
| **Dev**     | `http://127.0.0.1:5000/api`                      | `@app.route('/api/profile')` etc.| `http://127.0.0.1:5000/api/profile` |
| **Prod**    | `https://api.xlsvc.jsilverman.ca/api`            | same `/api/...` routes            | `https://api.xlsvc.jsilverman.ca/api/profile` |

- **Backend**: All routes use an `/api` prefix; hardcoded URLs in `main.py` (`file_url`, `callback_url`) also use `/api/...`.
- **Frontend**: Dev and prod bases end with `/api`, so `${API_BASE}/profile` -> `.../api/profile`.

So we have "api" in two places: **subdomain** `api.` (e.g. `api.xlsvc.jsilverman.ca`) and **path** `/api` (e.g. `.../api/profile`). That's the "double api" (pre + post).

---

## Findings

1. **Frontend and backend match** -- Dev and prod URLs built from the current base hit the right routes. Nothing is broken.
2. **The path `/api` is required today** -- If you removed `/api` from the frontend base (e.g. base = `https://api.xlsvc.jsilverman.ca`), then `${API_BASE}/profile` would be `.../profile`. The backend only serves `/api/profile`, so that would 404. So keep the path `/api` until the backend is changed.
3. **Do we need both subdomain and path?** -- No. Right now we need the path because the backend is mounted that way. If you move backend routes to root, you only need the subdomain (no path `/api`).

---

## Option A: Keep current (no code change)

- **Frontend prod base**: `https://api.xlsvc.jsilverman.ca/api`
- **Backend**: No change.
- **Pros**: Correct and stable.
- **Cons**: URL looks redundant (api subdomain + /api path).

---

## Option B: Subdomain-only (remove path `/api`)

**Goal**: Base = `https://api.xlsvc.jsilverman.ca` (no trailing `/api`).

### Backend (`xlsvc`)

1. **Routes**: Change every `@app.route('/api/...')` to `@app.route('/...')` in `main.py` (~30 decorators).
2. **Hardcoded URLs** in `main.py`: `file_url` -> `/download-with-token/`, `callback_url` -> `/processing-callback`.
3. **Tests**: Update all request paths from `/api/...` to `/...` in backend tests.

### Frontend (`xlsvc-frontend`)

1. **apiBase.js**: Prod base `https://api.xlsvc.jsilverman.ca`, dev base `http://127.0.0.1:5000` (no `/api`).
2. **Frontend tests**: Update expected prod base in `apiBase.test.js` if needed.

### Deployment / proxy

- If a reverse proxy strips a path prefix, ensure it does **not** strip `/api` once routes are at root (or serve the app at root on `api.xlsvc.jsilverman.ca`).

### Checklist (Option B)

- [ ] `main.py`: replace all `@app.route('/api/...')` with `@app.route('/...')`
- [ ] `main.py`: update `file_url` and `callback_url` to `/download-with-token/` and `/processing-callback`
- [ ] Backend tests: paths `/api/...` -> `/...`
- [ ] Frontend `apiBase.js`: prod `https://api.xlsvc.jsilverman.ca`, dev `http://127.0.0.1:5000`
- [ ] Frontend unit tests: expected prod base without `/api` if asserted
- [ ] Smoke-test dev and prod (login, profile, files, automated processing callback)

---

## Recommendation

- **Short term**: Use **Option A**. Production is correct and stable.
- **When you want subdomain-only URLs**: Do **Option B** in one coordinated change (backend + frontend + tests), then run full tests and a prod smoke test.

---

## Reference

- Backend routes: `main.py` -- search for `@app.route('/api/`.
- Frontend base: `xlsvc-frontend/src/apiBase.js` -- `getApiBase()` and `API_BASE`.
