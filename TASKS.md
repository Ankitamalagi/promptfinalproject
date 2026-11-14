# MVP Implementation Tasks

Use this checklist in order. Complete one small task at a time and verify it before moving forward.

## Phase 0 — Repository and environment

- [x] T-001 Create repository and project folder.
- [x] T-002 Create Python virtual environment.
- [x] T-003 Add `requirements.txt`.
- [x] T-004 Add `.gitignore` and `.env.example`.
- [x] T-005 Create FastAPI application with `/api/health`.
- [x] T-006 Run the server locally and open `/docs`.

**Acceptance:** FastAPI starts locally, health endpoint returns success, and no credentials are committed.

## Phase 1 — Request models and input handling

- [x] T-101 Define Pydantic request and response models.
- [x] T-102 Accept `user_message`, optional `retrieved_content`, `sources`, and `request_id`.
- [x] T-103 Add input length limits and source validation.
- [x] T-104 Preserve original input separately from normalized analysis text.
- [x] T-105 Add tests for valid, missing, malformed, and oversized requests.

**Acceptance:** Invalid requests receive clear validation errors; user and retrieved content remain distinguishable.

## Phase 2 — Detection engine

- [x] T-201 Define a finding data structure.
- [x] T-202 Add a small, documented set of defensive detection rules.
- [x] T-203 Identify possible instruction override indicators.
- [x] T-204 Identify possible data-extraction and role/tool-manipulation indicators.
- [x] T-205 Identify obfuscation and security-bypass indicators.
- [x] T-206 Attach source field and rule ID to each finding.
- [x] T-207 Add benign-text false-positive tests and direct/indirect test cases.

**Acceptance:** Detector returns explainable findings and does not claim certainty from a single phrase.

## Phase 3 — Risk scoring

- [x] T-301 Implement category weights and caps (25/25/20/10/10/10).
- [x] T-302 Ensure score is always between 0 and 100 with proper capping.
- [x] T-303 Return category score breakdown with per-category limits.
- [x] T-304 Map scores to low/medium/high/critical levels (configurable thresholds).
- [x] T-305 Make thresholds configurable via `app/core/config.py`.
- [x] T-306 Test empty findings, boundaries, maximum score, and deterministic scoring.

**Acceptance:** Same input and rules produce deterministic scores; repeated matches cannot exceed the maximum (100).

## Phase 4 — Policy engine

- [x] T-401 Define server-side policy configuration.
- [x] T-402 Implement ALLOW.
- [x] T-403 Implement FLAG as a held decision.
- [x] T-404 Implement BLOCK as a rejected decision.
- [x] T-405 Implement SANITIZE as a separate transformed candidate.
- [x] T-406 Re-scan sanitized candidate before provider use.
- [x] T-407 Ensure client cannot override server policy.
- [x] T-408 Test all policy paths.

**Acceptance:** Flagged and blocked requests are not forwarded. Sanitization is never treated as automatically safe.

## Phase 5 — Scan API

- [x] T-501 Implement `POST /api/scan`.
- [x] T-502 Return findings, score, risk level, policy, and decision.
- [x] T-503 Ensure scan endpoint never calls the provider.
- [x] T-504 Add API tests.

**Acceptance:** Scan endpoint works without an LLM key or network access.

## Phase 6 — Provider integration

- [x] T-601 Define provider interface.
- [x] T-602 Implement fake provider for tests and offline demos.
- [x] T-603 Implement optional OpenAI adapter.
- [x] T-604 Add timeout and safe error handling.
- [x] T-605 Implement `POST /api/chat`.
- [x] T-606 Assert BLOCK and FLAG make zero provider calls.
- [x] T-607 Ensure only approved, re-scanned content is forwarded.

**Acceptance:** Provider is called only after the gateway's required checks pass. Automated tests use a fake provider.

## Phase 7 — Audit and configuration

- [x] T-701 Create SQLite database and audit table.
- [x] T-702 Store minimal security event metadata.
- [x] T-703 Add `GET /api/logs` with pagination.
- [x] T-704 Add `GET /api/config` without secrets.
- [x] T-705 Test persistence and secret redaction.

**Acceptance:** Audit events survive restart and do not contain raw prompts or credentials by default.

## Phase 8 — Dashboard

- [x] T-801 Create dashboard HTML structure.
- [x] T-802 Add CSS layout and status indicators.
- [x] T-803 Connect JavaScript to config/log endpoints.
- [x] T-804 Display request counts and policy decisions.
- [x] T-805 Add a safe sample scan form.
- [x] T-806 Verify dashboard does not expose secrets.

**Acceptance:** Local dashboard displays real backend audit data.

## Phase 9 — Quality and demonstration

- [x] T-901 Run full test suite.
- [x] T-902 Add direct-injection demo cases.
- [x] T-903 Add indirect-injection demo cases using retrieved content.
- [x] T-904 Demonstrate ALLOW, FLAG, BLOCK, SANITIZE.
- [x] T-905 Verify provider-call behaviour for each policy.
- [x] T-906 Update README and CHANGELOG.
- [x] T-907 Prepare architecture explanation and demo script.

**Acceptance:** A repeatable demonstration shows the problem, gateway decision, evidence, and provider-call outcome.

**Acceptance:** A repeatable demonstration shows the problem, gateway decision, evidence, and provider-call outcome.

## Suggested MVP milestone

The first useful milestone is Phases 0–5: a working FastAPI scan service with detection, scoring, and policy decisions. Add provider integration only after these controls are tested.
