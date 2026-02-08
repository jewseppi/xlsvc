# Dead Code Removal Report

**Date:** 2026-01-29
**Phase:** Phase 1 (Dead code removal) per `docs/REFACTORING.md` Section 5

---

## Summary

Removed **1 dead function** from `main.py` and **1 unused import**. Total lines removed: **~32**.

---

## Items Removed

### 1. `analyze_excel_file()` function

| Detail | Value |
|--------|-------|
| **File** | `main.py` |
| **Lines** | 2268–2298 (31 lines) |
| **What** | Standalone function that loaded a workbook and checked hardcoded columns F/G/H/I for zero/empty values to decide which rows to delete. |
| **Why dead** | Never called anywhere in backend or frontend. Fully superseded by the `process_file()` route which uses dynamic `filter_rules` passed from the frontend, plus `capture_row_data()` for report generation. The hardcoded F/G/H/I logic is incompatible with the current design. |
| **Verified** | `grep -r 'analyze_excel_file' excel/xlsvc/ excel/xlsvc-frontend/` — no matches in any source file. |
| **Was excluded** | `# pragma: no cover` since coverage push. |
| **Impact** | None. No callers, no tests to remove (tests were never written per policy). |

### 2. `import random`

| Detail | Value |
|--------|-------|
| **File** | `main.py` |
| **Lines** | 1 line |
| **What** | `import random` at module level. |
| **Why dead** | `random.` is never referenced anywhere in main.py. Leftover from earlier prototype. |
| **Verified** | `grep 'random\.' main.py` — no matches. |
| **Impact** | None. |

---

## Items NOT Removed (verified as live)

### `subscribe()` route + `subscribers` table

| Detail | Value |
|--------|-------|
| **Route** | `POST /api/subscribe` |
| **Called by** | `xlsvc-frontend/public/landing.html` line 1370 — the landing page email subscription form POSTs to `https://api.xlsvc.jsilverman.ca/api/subscribe`. |
| **Status** | **Live code.** Tests added to cover all branches (success, duplicate 409, invalid email 400, empty email 400, email normalization, server error 500). |

---

## Files Changed

| File | Change |
|------|--------|
| `main.py` | Removed `analyze_excel_file()` function and `import random`. |

---

## Verification

- `grep -r 'analyze_excel_file' excel/xlsvc/ excel/xlsvc-frontend/` — no matches.
- `grep 'random\.' main.py` — no matches.
- `subscribe()` confirmed live via `xlsvc-frontend/public/landing.html` line 1370.
- No linter errors introduced.
- Coverage threshold remains `--cov-fail-under=100`.
- Test coverage added for `subscribe()` (6 tests in `test_main_routes.py::TestSubscribe`).
