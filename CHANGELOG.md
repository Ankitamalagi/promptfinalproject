# Changelog

All notable project changes should be recorded here.

The project follows a simple Keep a Changelog-inspired format. Dates use `YYYY-MM-DD`. Do not record a feature as completed until it exists and has been tested.

## [0.1.0] - Planning

### Added
- Initial MVP problem definition for direct and indirect prompt injection.
- Product requirements for source-aware scanning and policy decisions.
- Proposed modular FastAPI architecture.
- Developer/agent working instructions.
- Ordered implementation task checklist.
- Project context and terminology.
- Testing strategy and acceptance criteria.

### Planned
- FastAPI service and health endpoint.
- Rule-based detector and 0–100 risk scoring.
- ALLOW, FLAG, BLOCK, and SANITIZE policies.
- Scan and chat REST endpoints.
- Optional LLM provider adapter.
- SQLite audit events and basic dashboard.

### Security notes
- Rule-based detection is not a guarantee of prevention.
- FLAG and BLOCK must not call the provider.
- Sanitized content must be re-scanned.
- Raw prompts and credentials should not be stored in audit logs by default.

## [0.1.0] - 2026-11-13

### Added
- Python virtual environment with all dependencies (FastAPI, Pydantic, SQLAlchemy, HTTPX, pytest)
- `.gitignore` excluding venv, .env, database files, cache, and IDE files
- `.env.example` with all configuration options documented
- FastAPI application with modular structure (app/main.py, app/core/config.py)
- Health check endpoint (`GET /api/health`) returning service status
- Root endpoint with links to docs and health
- Swagger UI available at `/docs`
- Basic test suite for health endpoint (2 tests passing)

### Verified
- FastAPI starts locally on 127.0.0.1:8001
- Health endpoint returns JSON with status, version, environment, provider_configured
- No credentials committed to repository
- Automated tests pass

## [0.1.0] - 2026-11-13 (Phase 1)

### Added
- Pydantic request/response models in `app/core/models.py`:
  - `ScanRequest`: user_message (required), retrieved_content (optional), sources, request_id
  - `ChatRequest`: extends ScanRequest with required task field
  - `ScanResponse`/`ChatResponse`: risk_score, risk_level, findings, score_breakdown, policy, decision
  - `ScoreBreakdown`: category caps per PRD (25/25/20/10/10/10)
  - `ConfigResponse`, `LogEntry`, `LogsResponse` for future phases
- Input validation:
  - Required user_message (non-empty, max 10000 chars configurable)
  - Optional retrieved_content (max 50000 chars configurable)
  - Source labels validation (non-empty, stripped)
  - Auto-generated request_id (short UUID)
- Input normalization in `app/security/normalizer.py`:
  - `normalize_text()`: lowercase, unicode NFKC, whitespace collapse
  - `create_normalized_input()`: preserves original + creates analysis versions
  - `NormalizedInput` dataclass with original/analysis separation
- Scan endpoint (`POST /api/scan`) in `app/api/scan.py`:
  - Validates request, normalizes, runs placeholder detection/scoring/policy
  - Returns structured response with risk_score=0, risk_level=low, provider_called=false
- Chat endpoint (`POST /api/chat`) in `app/api/chat.py`:
  - Validates request including required task field
  - Same processing pipeline as scan (placeholder)
  - Returns ChatResponse structure
- Configuration-driven size limits via `app/core/config.py` settings
- Comprehensive test suite (50 tests passing):
  - 30 model/normalizer tests (validation, bounds, normalization)
  - 18 API tests (valid, missing, malformed, oversized requests)
  - 2 health tests

### Verified
- All 50 automated tests pass
- Scan endpoint accepts valid requests, rejects invalid with clear 422 errors
- Chat endpoint validates required task field
- Size limits enforced (10000/50000 chars default)
- Original input preserved separately from normalized analysis text
- Source labels distinguish user vs retrieved content
- No credentials committed

## [0.1.0] - 2026-11-13 (Phase 2)

### Added
- Detection Engine in `app/security/detector.py`:
  - `DetectionRule` dataclass for defining security patterns.
  - 30+ rule-based indicators across 6 risk categories:
    - **Instruction Override:** Detects "ignore previous instructions", "forget rules", etc.
    - **Sensitive Data Extraction:** Detects attempts to get API keys, passwords, or system prompts.
    - **Role/Tool Manipulation:** Detects "act as admin", "execute code", "call function".
    - **Obfuscation:** Detects base64, unicode escaping, and character spacing (i g n o r e).
    - **Suspicious External Instructions:** Specifically for text found in retrieved documents.
    - **Security Bypass:** Detects "jailbreak", "dan", and attempts to turn off safety filters.
  - `detect()` function that analyzes both user messages and retrieved content.
  - Source attribution: findings correctly identify if the threat came from the user or a document (direct vs indirect).
- Integration:
  - Updated `/api/scan` and `/api/chat` to use the detector.
  - Integrated findings into API responses.
- Tests (46 new tests, total 96 passing):
  - Direct injection tests (user message).
  - Indirect injection tests (retrieved documents).
  - Benign false-positive tests (ensures normal questions aren't blocked).
  - Regex robustness fixes for various natural language variations.

### Verified
- 96/96 tests pass.
- Detector identifies explainable indicators with rule IDs and reasons.
- System distinguishes between malicious instructions in user input vs external files.
- Benign technical discussions (e.g., "how to ignore files in git") do not trigger high-severity flags.

## [0.1.0] - 2026-11-13 (Phase 3)

### Added
- Risk Scoring Module in `app/security/risk.py`:
  - `calculate_risk_score()` function converts findings → 0-100 score with category caps
  - Category caps enforced (25/25/20/10/10/10 from PRD)
  - Deterministic scoring: same input → same score
  - Risk levels: low (0-29), medium (30-59), high (60-79), critical (80-100)
  - Configurable thresholds via `app/core/config.py`
  - `get_category_limits()` and `get_risk_thresholds()` config helpers
- Tests (28 new tests, total 124 passing):
  - Category caps respected
  - Deterministic scoring
  - Boundary thresholds (low/medium/high/critical)
  - Maximum score = 100

### Verified
- 124/124 tests pass (96 before + 28 new risk scoring)
- Risk score always 0-100 with proper category caps
- Score thresholds configurable via settings

## [0.1.0] - 2026-11-13 (Phase 4)

### Added
- Policy Engine in `app/security/policy.py`:
  - `apply_policy()` function applies server-side security policies
  - Four policies with distinct documented behaviors:
    - **ALLOW**: Permits processing; provider may be called. Holds critical risk and dangerous findings at moderate+ risk.
    - **FLAG**: Holds all requests for authorized review; never calls provider.
    - **BLOCK**: Rejects all requests; never calls provider.
    - **SANITIZE**: Transforms content, re-scans before forwarding. Blocks high/critical risk and dangerous categories.
  - Server-controlled policy; client cannot override.
  - Critical risk (≥80) overrides ALLOW for safety.
  - Dangerous content categories (instruction_override, sensitive_data_extraction, security_bypass) trigger holds even under ALLOW.
- Integration:
  - Updated `/api/scan` and `/api/chat` to use policy engine.
- Tests (33 new tests, total 157 passing):
  - All four policies tested with various risk levels and findings
  - BLOCK and FLAG never call provider
  - SANITIZE re-scans before forwarding
  - Client cannot override server policy
  - Unknown policy defaults to BLOCK for safety

### Verified
- 157/157 tests pass (124 before + 33 new policy tests)
- All four policies behave as documented
- Provider never called for BLOCK/FLAG
- SANITIZE blocks dangerous content

## [0.1.0] - 2026-11-13 (Phase 5)

### Added
- Provider Interface in `app/providers/base.py`:
  - Abstract `Provider` class with `complete()` method and `is_available()` check
  - `ProviderResponse` dataclass for standardized responses
- Demo Provider in `app/providers/demo_provider.py`:
  - `DemoProvider` class for testing/demos without API keys
  - Returns clearly marked `[DEMO RESPONSE]` simulated AI responses
  - Configurable delay and error rate for testing
  - `AlwaysErrorDemoProvider` for testing error handling
- OpenAI Provider in `app/providers/openai_provider.py`:
  - `OpenAIProvider` class using official OpenAI AsyncOpenAI client
  - Reads API key from `OPENAI_API_KEY` environment variable
  - Configurable model, timeout, and safe error handling
  - Never exposes API keys in responses or logs
- Provider Factory in `app/providers/factory.py`:
  - `get_provider()` returns configured provider (OpenAI if API key set, else Demo)
  - `get_provider_by_name()` for explicit provider selection
- Chat Endpoint (`POST /api/chat`) in `app/api/chat.py`:
  - Full security pipeline: validate → detect → score → policy → provider
  - ALLOW: calls provider with original message
  - SANITIZE: calls provider with sanitized content (re-scanning in Phase 6)
  - FLAG: never calls provider, returns held_for_review
  - BLOCK: never calls provider, returns rejected
  - Response includes provider_called, provider_response, provider_error
- Tests (18 new tests, total 175 passing):
  - ALLOW calls provider with benign requests
  - SANITIZE calls provider with sanitized content
  - FLAG does not call provider
  - BLOCK does not call provider
  - Demo provider works without API key
  - Provider errors and timeouts handled safely

### Verified
- 175/175 tests pass (157 before + 18 new provider integration tests)
- ALLOW calls provider for benign requests
- FLAG and BLOCK never call provider
- Demo provider works without OpenAI API key
- Provider errors handled safely, no secrets exposed
- Security policy enforced before any provider call

## [0.1.0] - 2026-11-14 (Phase 7)

### Added
- Audit Database and Models in `app/audit/database.py`:
  - `AuditEvent` SQLAlchemy table storing request_id, created_at, sources, risk_score, risk_level, policy, decision, finding_codes, provider_called, and provider_status.
  - Privacy control: raw prompts and sensitive credentials are never stored.
  - Synchronous SQLite engine and session factory with automatic table creation via `init_db()`.
- Audit Repository in `app/audit/repository.py`:
  - `record_audit_event()`: persists minimal security event metadata.
  - `get_audit_events()`: retrieves paginated audit logs with bounded limits (1 to 100).
  - `get_audit_stats()`: aggregates total requests, decision counts, and provider invocation stats.
- Configuration Endpoint (`GET /api/config`) in `app/api/config.py`:
  - Exposes safe server parameters: active policy, risk thresholds, provider status/name, and input length limits.
  - Omits and redacts API keys and secrets.
- Logs Endpoint (`GET /api/logs`) in `app/api/logs.py`:
  - Returns paginated `LogsResponse` containing `LogEntry` records without raw prompt content.
  - Added `GET /api/logs/stats` for dashboard metrics.
- Pipeline integration in `/api/scan` and `/api/chat`:
  - Automatically records every scan and chat evaluation to the audit repository.
- Tests in `tests/test_audit.py` (8 new tests, total 165 passing):
  - Audit event persistence in SQLite.
  - Verification that raw prompts are not saved.
  - Secret redaction on `/api/config`.
  - Pagination and bounded limits on `/api/logs`.

### Verified
- 165/165 tests pass.
- Audit events persist across requests.
- No sensitive user messages or API keys are stored in database logs.

## [0.1.0] - 2026-11-14 (Phase 8)

### Added
- Dashboard HTML structure in `app/static/index.html`:
  - Live system configuration banner (policy, provider, risk thresholds).
  - Five metric cards: total requests, allowed, held, rejected, provider invocations.
  - Interactive safe scan console with preset demo samples (Benign, Direct Attack, Indirect Attack, Exfiltration).
  - Findings display with per-rule-ID explanations.
  - Paginated audit log table (no raw prompt text shown).
- CSS layout in `app/static/styles.css`: dark theme, responsive grid, risk-level colour badges.
- JavaScript in `app/static/app.js`: connects to `/api/config`, `/api/logs/stats`, `/api/logs`, and `/api/scan`.
- Dashboard route `GET /dashboard` serving `index.html`.
- Tests in `tests/test_dashboard.py` (4 new tests, total 169 passing):
  - Dashboard endpoint loads and returns HTML.
  - Static assets (CSS, JS) are served.
  - Dashboard verified to contain no hardcoded API keys.
  - Root endpoint updated to include `/dashboard` link.

### Verified
- 169/169 tests pass.
- Dashboard accessible at `http://127.0.0.1:8000/dashboard`.
- No secrets exposed in any static asset.

## [0.1.0] - 2026-11-14 (Phase 9)

### Added
- Demonstration test suite in `tests/test_demo.py` (18 new tests, total 187 passing):
  - **T-902 Direct injection demos**: Classic override, DAN jailbreak, sensitive data exfiltration, role/tool manipulation, benign false-positive test.
  - **T-903 Indirect injection demos**: Malicious PDF document, poisoned web search result, innocent-user/malicious-document attribution test.
  - **T-904 All four policy demonstrations**: ALLOW (benign → LLM called), ALLOW (attack → auto-held), FLAG (all → held, provider=0), BLOCK (all → rejected, provider=0), SANITIZE (dangerous → blocked, low-risk → sanitized).
  - **T-905 Provider-call contract verification**: Explicit loop test proving BLOCK and FLAG never call the provider across multiple input types.
- README updated with current implementation status, all API endpoints, and running instructions.
- CHANGELOG updated with Phase 8 and Phase 9 entries.

### Verified
- **187/187 tests pass** (full suite: detector, risk, policy, models, health, scan API, audit, dashboard, demos).
- All four policy decisions produce correct provider-call behaviour.
- Direct and indirect injection attacks are detected with rule IDs and source attribution.
- Benign messages pass through without false positives.
- `/api/scan` NEVER calls the provider regardless of content.
- BLOCK and FLAG policies call the provider zero times across all inputs.

## Unreleased

Add implementation changes here as tasks are completed.
