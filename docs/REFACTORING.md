# Refactoring: coverage, dead code, extraction

Coverage strategy, dead code, extraction candidates, and the refactor TODO.

---

## Prerequisites (before refactoring)

- [x] Backend test coverage at 100% on *live* code (dead code and entry points excluded).
- [x] CI green with `--cov-fail-under=100`.
- [x] `.coveragerc` and pragmas match this doc (see Sections 1, 2, 4).

---

## 1. Coverage strategy for dead code

- **Do not add tests for dead code.** Remove it later; don’t invest in testing it.
- **Exclude dead code from coverage** so the 100% bar applies only to live code:
  - **Method:** `# pragma: no cover` on each dead function/block in Section 2 (or omit in `.coveragerc`; if you switch, document it here).
- **When you remove dead code:** Delete the code and remove the pragma/omit. No tests to delete.

---

## 2. Dead code inventory

See `docs/DEAD_CODE_REMOVAL.md` for the full report.

| File   | Name | Status |
|--------|------|--------|
| ~~main.py~~ | ~~`analyze_excel_file`~~ | **Removed.** Superseded by `process_file()` + dynamic filter_rules. Verified: no callers in backend or frontend. |
| ~~main.py~~ | ~~`import random`~~ | **Removed.** Never referenced (`random.` has zero matches). |
| main.py | `subscribe()` + `POST /api/subscribe` + `subscribers` table | **Live.** Called by `xlsvc-frontend/public/landing.html` (line 1370). Tests added. |

**Notes:**

- Other standalone modules (cleanup_files.py, process_uno.py, deletion_report.py) are in use (cron, GitHub Actions, main/process_uno).

---

## 3. Omit list (excluded from coverage)

These files are out of the 100% denominator. Keep in sync with `.coveragerc`.

| File | Reason |
|------|--------|
| passenger_wsgi.py | WSGI entry; imports `app` from main. |
| tests/create_test_excel.py | Test data builder; not production code. |
| process_uno.py | Runs inside LibreOffice only (UNO); not testable in pytest. |
| cleanup_files.py | Cron entry script; runs in subprocess so coverage can't see it. |
| github_app.py | Requires GitHub App credentials and external API access; not testable in pytest. |

---

## 4. Extraction candidates (main.py → smaller modules)

**Do not extract until 100% coverage on live code.** Then extract **one module at a time**; run tests after each step.

| Module | What moves | Notes |
|--------|------------|--------|
| auth_helpers (or security.py) | `validate_password_strength`, `is_admin_user`, `validate_invitation_token`, `generate_download_token`, `verify_download_token`, `rate_limit` | Some need `app`, `request`, `get_db`; pass as params or keep in main. |
| file_utils.py | `calculate_file_hash`, `get_file_path`, `allowed_file`, `validate_excel_file`, `ensure_directories` | `get_file_path` / `ensure_directories` use `app.config`; pass config or keep in main. |
| db.py | `get_db`, `init_db` (and schema) | Tightly coupled to Flask; optional to extract. |
| processing_helpers.py | `column_to_index`, `is_empty_or_zero`, `evaluate_cell_value` | Already tested in test_processing_helpers.py; main and process_uno use these; consider one shared impl. |
| cleanup.py | `cleanup_old_files()` | main.py and cleanup_files.py could import from here. |

---

## 5. Order of operations (Phase 1 & 2)

**Phase 1: Dead code removal** — **COMPLETE** (see `docs/DEAD_CODE_REMOVAL.md`)

- ~~Use Section 2 as the checklist. Remove one item at a time.~~
- ~~After each: run tests; remove the `# pragma: no cover` (or omit) for that item.~~

**Phase 2: Extract modules** — **COMPLETE**

All five extraction candidates from Section 4 have been extracted:

| Module | Status | Coverage |
|--------|--------|----------|
| `auth_helpers.py` | Extracted | 88% |
| `file_utils.py` | Extracted | 95% |
| `db.py` | Extracted | 73% |
| `processing_helpers.py` | Extracted (already existed) | 100% |
| `cleanup.py` | Extracted | 52% |
| `macro_generator.py` | Extracted (bonus) | 100% |
| `github_app.py` | Extracted (bonus, omitted from coverage — requires GitHub App credentials) | N/A |

`main.py` now imports from all extracted modules. All 172 tests pass. Overall coverage: 91% (up from 68%).

**Next:** Raise coverage toward 100% on the extracted modules (especially `cleanup.py` and `db.py`).

**Optional: API cleanup**

- When you want subdomain-only URLs (no path `/api`), follow **API.md** Option B: backend routes to root, then frontend base without `/api`, then test and smoke prod.

---

## Reference

- **API base and double api:** `docs/API.md`
- **Coverage config:** `.coveragerc`
