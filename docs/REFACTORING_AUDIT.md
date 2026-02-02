# xlsvc API – Refactoring audit and coverage reference

This document is the single source of truth for **dead code**, **coverage strategy**, and **extraction candidates**. Use it to reach 100% test coverage on live code first, then to remove dead code and extract modules systematically without breaking coverage.

**Last updated:** 2026-01-29

---

## 1. Coverage strategy for dead code

- **We do not add tests for dead code.** Dead code will be removed later; we do not invest in testing it.
- **We exclude dead code from coverage** so that the 100% threshold applies only to *live* code. How we exclude:
  - **Chosen method:** Add `# pragma: no cover` to each dead function or block listed in the Dead code inventory (Section 2). Alternatively, add an omit pattern in `.coveragerc` for those functions; if you switch to .coveragerc, document it here.
- **When we remove dead code later:** Delete the code and remove the corresponding `# pragma: no cover` (or omit entry). There are no tests to delete for dead code because we never added them.
- **Returning to this state:** This doc plus the coverage config (`.coveragerc` + pragmas) define “current state.” Use Section 5 (Order of operations) as the checklist.

---

## 2. Dead code inventory

Do **not** add tests for these. Exclude from coverage until removed.

| File | Line range | Name | Reason | Action |
|------|------------|------|--------|--------|
| main.py | 2268–2298 | `analyze_excel_file` | Never called. Superseded by inline logic in `process_file()` (filter_rules + openpyxl + `capture_row_data`). Hardcoded F/G/H/I columns; current design uses dynamic filter_rules. | Exclude from coverage (`# pragma: no cover`). Do not add tests. Remove in Phase 4. |
| main.py | 571–608 | `subscribe()`, route `POST /api/subscribe`, table `subscribers` | Frontend (xlsvc-frontend) has no references to `/api/subscribe`. Confirm with product/frontend if feature is retired. | If confirmed dead: exclude from coverage, then remove route and table (or document “keep for future use” and add tests). |

**Notes:**

- `init_db()` in main.py creates the `subscribers` table (see schema around line 362). If we remove the subscribe feature, decide whether to drop the table in init or add a migration.
- No other dead API routes or functions were found; all other standalone modules (cleanup_files.py, process_uno.py, deletion_report.py) are in use (cron, GitHub Actions, main/process_uno).

---

## 3. Extraction candidates (file.py pattern)

Code in **main.py** that could move into contained modules, following the pattern of `deletion_report.py` and `cleanup_files.py`. **Do not move until 100% coverage on live code is achieved.** Use this list when doing Phase 4 (extract modules one at a time; run tests after each extraction).

| Suggested module | What would move | Dependencies / notes |
|------------------|-----------------|------------------------|
| auth_helpers.py (or security.py) | `validate_password_strength`, `is_admin_user`, `validate_invitation_token`, `generate_download_token`, `verify_download_token`, `rate_limit` | Some need `app`, `request`, `get_db`; may stay in main or receive them as params. |
| file_utils.py | `calculate_file_hash`, `get_file_path`, `allowed_file`, `validate_excel_file`, `ensure_directories` | `get_file_path` and `ensure_directories` use `app.config`; pass config or keep in main. |
| db.py | `get_db`, `init_db` (and schema) | Tightly coupled to Flask app; optional to extract. |
| processing_helpers.py | `column_to_index`, `is_empty_or_zero`, `evaluate_cell_value` | Already tested in test_processing_helpers.py; main and process_uno both use column_to_index / is_empty_or_zero. process_uno has its own zero-based column_to_index; consider one shared implementation. |
| cleanup.py | `cleanup_old_files()` | Large function; main.py and cleanup_files.py could import from cleanup.py. cleanup_files.py is currently a thin wrapper around main.cleanup_old_files and main.init_db. |

---

## 4. Omit list (always excluded from coverage)

These files are excluded from the 100% coverage denominator regardless of dead code. They are entry points or test helpers, not application logic.

| File | Reason |
|------|--------|
| passenger_wsgi.py | WSGI entry (3 lines); imports `app` from main. |
| tests/create_test_excel.py | Test data builder for tests; not production code. |
| process_uno.py | Runs inside LibreOffice only (UNO-dependent); not testable in pytest. |

Keep this list in sync with `.coveragerc` (e.g. `[run] omit = ...`).

---

## 5. Order of operations

**A. Ref doc and coverage config**

- This document exists and is updated as needed.
- `.coveragerc` exists: omits `passenger_wsgi.py`, `tests/create_test_excel.py`.
- Dead code (Section 2) is excluded from coverage via `# pragma: no cover` (or .coveragerc).

**B. Add tests until 100% on live code**

- Add tests for: main.py (all live routes and helpers), deletion_report.py, cleanup_files.py, process_uno.py (unit-testable parts; UNO-dependent code can be `# pragma: no cover`), conftest.py if desired.
- Run `pytest --cov` with `--cov-fail-under=100` until it passes.

**C. Remove dead code (Phase 4)**

- Use Section 2 as the checklist. Remove one item at a time.
- After each removal: run the test suite; remove the `# pragma: no cover` (or omit) for that item. No tests to delete for dead code.

**D. Extract modules (Phase 4)**

- Use Section 3 as the backlog. Extract one module at a time.
- After each extraction: run the test suite; update imports in main.py and any other callers. This keeps refactors systematic and easy to roll back.
