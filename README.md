# xlsvc Backend

Flask REST API for the xlsvc Excel batch row deletion tool.

## URLs

| Environment | URL |
|-------------|-----|
| API (dev) | `http://127.0.0.1:5000/api` |
| API (prod) | `https://api.xlsvc.jsilverman.ca/api` |
| Health check | `GET /api/health` |

## Stack

- Python 3.11, Flask 2.3
- SQLite (xlsvc.db)
- Flask-JWT-Extended (auth)
- Flask-CORS
- openpyxl (Excel processing)
- GitHub App integration (automated processing via Actions)

## Getting Started

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -c "from main import init_db; init_db()"
python -m flask --app main run --debug
```

Server starts at `http://127.0.0.1:5000`. Set `SECRET_KEY` env var for JWT (defaults to dev key).

## Testing

```bash
pytest tests/                          # Run all tests
pytest tests/ --cov-report=term-missing  # With missing lines
```

Coverage threshold is **100%** (`--cov-fail-under=100`). See `docs/COVERAGE_PLAN.md` for details.

## Project Structure

```
main.py              Flask app (all routes, helpers, DB schema)
deletion_report.py   Generates Excel deletion report workbooks
process_uno.py       LibreOffice UNO script (GitHub Actions only)
cleanup_files.py     Cron script: deletes files older than 24h
passenger_wsgi.py    WSGI entry point for Passenger hosting

docs/
  API.md             API URL convention and alignment
  COVERAGE_PLAN.md   How to maintain 100% test coverage
  DEAD_CODE_REMOVAL.md  What was removed and what was kept
  REFACTORING.md     Extraction candidates and phase plan

tests/
  conftest.py        Fixtures (client, auth, DB, sample files)
  test_api.py        API integration tests
  test_main_routes.py    Route-level tests
  test_main_helpers.py   Helper function tests
  test_process_file.py   Processing tests
  test_processing_helpers.py  Cell evaluation tests
  test_cleanup_script.py     Cleanup cron tests
  test_deletion_report.py    Report generation tests
```

## Database

SQLite file `xlsvc.db` with 5 tables:

| Table | Purpose |
|-------|---------|
| `users` | Accounts (email, password, is_admin) |
| `files` | Uploaded and generated files |
| `processing_jobs` | Automated job tracking |
| `subscribers` | Landing page email signups |
| `invitation_tokens` | Registration invitations |

Schema is created/migrated by `init_db()` in `main.py`.

## API Routes (28 total)

**Auth**: login, register, profile, validate-invitation
**Files**: upload, list, download, download-with-token, get-macro, generated files, history
**Processing**: manual process, automated process, job status, processing callback
**Admin**: create/list/expire invitations, list/detail/delete users
**Utility**: health, subscribe, cleanup-files, debug/storage, test-github, test-dispatch

All routes prefixed with `/api/`. See `docs/API.md` for URL convention.

## Deployment

Automated via GitHub Actions (`.github/workflows/deploy.yml`):
1. Tests must pass on `main` branch
2. SSH + rsync to shared hosting (Passenger)
3. Cron job for `cleanup_files.py` at 2 AM UTC

## Related

- **Frontend repo**: `../xlsvc-frontend/`
- **Project overview**: `../PROJECT_OVERVIEW.md`
