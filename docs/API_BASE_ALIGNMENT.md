# API base URL alignment (frontend ↔ backend)

## Current state (aligned)

| Environment | Frontend API base (`xlsvc-frontend/src/apiBase.js`) | Backend routes (`xlsvc/main.py`) | Resulting URL example |
|-------------|------------------------------------------------------|----------------------------------|------------------------|
| **Dev**     | `http://127.0.0.1:5000/api`                          | `@app.route('/api/profile')` etc.| `http://127.0.0.1:5000/api/profile` ✓ |
| **Prod**    | `https://api.xlsvc.jsilverman.ca/api`                | same `/api/...` routes           | `https://api.xlsvc.jsilverman.ca/api/profile` ✓ |

- **Backend**: All routes are defined with an `/api` prefix (e.g. `/api/profile`, `/api/login`, `/api/files`). Hardcoded callback/download URLs in `main.py` (e.g. `file_url`, `callback_url`) also use `/api/...`.
- **Frontend**: Dev and prod bases both end with `/api`, so `${API_BASE}/profile` correctly becomes `.../api/profile`.

The “redundancy” (subdomain `api.` + path `/api`) is required with the current backend; removing `/api` from the frontend prod base would break production (404s).

---

## Option A: Keep current (no code change)

- **Frontend prod base**: `https://api.xlsvc.jsilverman.ca/api`
- **Backend**: No change.
- **Pros**: Already correct; no risk.
- **Cons**: URL looks redundant (api subdomain + /api path).

---

## Option B: Subdomain-only (remove `/api` path)

**Goal**: Use `https://api.xlsvc.jsilverman.ca` as the API base (no trailing `/api`).

### Backend (`xlsvc`)

1. **Routes**: Change every `@app.route('/api/...')` to `@app.route('/...')` in `main.py` (e.g. `/api/profile` → `/profile`). There are ~30 route decorators.
2. **Hardcoded URLs**: In `main.py` (process-automated / GitHub payload):
   - `file_url`: change `/api/download-with-token/` → `/download-with-token/`
   - `callback_url`: change `/api/processing-callback` → `/processing-callback`
3. **Tests**: In `tests/test_api.py`, `tests/test_process_file.py`, `tests/conftest.py`, update all request paths from `/api/...` to `/...`.

### Frontend (`xlsvc-frontend`)

1. **apiBase.js**: Set production base to `https://api.xlsvc.jsilverman.ca` (no `/api`).
2. **Dev**: Set dev base to `http://127.0.0.1:5000` (no `/api`) so `${API_BASE}/profile` → `http://127.0.0.1:5000/profile`.

### Deployment / proxy

- If a reverse proxy or Passenger strips a path prefix, ensure it does **not** strip `/api` once routes are at root (or adjust so the app is served at root on `api.xlsvc.jsilverman.ca`).

### Checklist (Option B)

- [ ] `main.py`: replace all `@app.route('/api/...')` with `@app.route('/...')`
- [ ] `main.py`: update `file_url` and `callback_url` to use `/download-with-token/` and `/processing-callback`
- [ ] Backend tests: update paths from `/api/...` to `/...`
- [ ] Frontend `apiBase.js`: prod `https://api.xlsvc.jsilverman.ca`, dev `http://127.0.0.1:5000`
- [ ] Frontend unit tests: update expected API base in `apiBase.test.js` (prod branch) if needed
- [ ] Smoke-test dev and prod (login, profile, files, automated processing callback)

---

## Recommendation

- **Short term**: Use **Option A** (current setup). Production is correct and stable.
- **If you want subdomain-only URLs**: Follow **Option B** in a single change (backend + frontend + tests) and then run full tests and a quick prod smoke test.
