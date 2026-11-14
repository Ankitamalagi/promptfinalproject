# Prompt Injection Security Gateway for AI Applications

A beginner-friendly MVP of a reusable security middleware that inspects user messages and externally retrieved content before an application forwards them to a Large Language Model (LLM).

## Why this project?

LLM applications may combine trusted application instructions with untrusted user messages and retrieved documents. If these trust boundaries are not preserved, malicious text in a user message, webpage, PDF, or email may try to influence the model.

The gateway adds an application-controlled security checkpoint between an AI application and its LLM provider.

> **Security limitation:** This MVP is defense-in-depth, not a complete prompt-injection solution. Rule-based detection can miss attacks and can flag harmless text. Never rely on the gateway alone to protect secrets, authorize actions, or secure tools.

## MVP goals

- Accept text with a declared source and request metadata.
- Inspect user-provided and externally sourced text separately.
- Detect suspicious indicators using explainable rules.
- Calculate a transparent risk score from 0 to 100.
- Apply `ALLOW`, `FLAG`, `BLOCK`, or `SANITIZE` handling.
- Forward only approved content through a provider adapter.
- Record privacy-conscious audit events.
- Expose REST endpoints and a small dashboard.
- Provide automated tests, including a test proving blocked requests do not call the provider.

## Proposed technology stack

- Python 3.12 or 3.13
- FastAPI, Pydantic, Uvicorn
- Python rule engine and regular expressions
- SQLite and SQLAlchemy
- HTTPX for provider communication
- OpenAI API as the first optional provider
- HTML, CSS, JavaScript, Chart.js for the dashboard
- Pytest for automated tests
- Git and GitHub for version control

## Main request flow

1. Client sends text, source metadata, and an optional policy.
2. API validates the request.
3. Gateway normalizes text without discarding the original.
4. Detector evaluates suspicious indicators.
5. Risk engine calculates a score and records evidence.
6. Policy engine decides whether to allow, hold, block, or sanitize.
7. Only a permitted, prepared request may reach the provider.
8. Gateway returns a structured result and stores a minimal audit event.

## Implementation Status

All 9 phases of the MVP are complete. **187 / 187 tests passing.**

| Phase | Description | Status |
|---|---|---|
| Phase 0 | Repository & environment setup | ✅ Done |
| Phase 1 | Request models & input validation | ✅ Done |
| Phase 2 | Rule-based detection engine (30+ rules) | ✅ Done |
| Phase 3 | Risk scoring (0–100 with category caps) | ✅ Done |
| Phase 4 | Policy engine (ALLOW / FLAG / BLOCK / SANITIZE) | ✅ Done |
| Phase 5 | `/api/scan` endpoint | ✅ Done |
| Phase 6 | Provider integration (Demo + OpenAI adapter) | ✅ Done |
| Phase 7 | SQLite audit log, `/api/logs`, `/api/config` | ✅ Done |
| Phase 8 | Web dashboard | ✅ Done |
| Phase 9 | Full demo test suite & documentation | ✅ Done |

## API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Analyze content and return a security decision without calling an LLM |
| `POST` | `/api/chat` | Analyze content and call the configured provider only when permitted |
| `GET` | `/api/config` | Return non-secret gateway configuration (policy, thresholds, provider) |
| `GET` | `/api/logs` | Return paginated audit events (no raw prompts stored) |
| `GET` | `/api/logs/stats` | Return aggregate decision counts for dashboard |
| `GET` | `/api/health` | Health check |
| `GET` | `/dashboard` | Web dashboard with live scan console and audit log viewer |

Interactive API documentation is available at `/docs` while the development server is running.

## Suggested project layout

```text
prompt-injection-security-gateway/
├── app/
│   ├── main.py
│   ├── api/
│   │   └── routes.py
│   ├── core/
│   │   ├── config.py
│   │   └── schemas.py
│   ├── security/
│   │   ├── normalizer.py
│   │   ├── detector.py
│   │   ├── risk.py
│   │   ├── policies.py
│   │   └── sanitizer.py
│   ├── providers/
│   │   ├── base.py
│   │   └── openai_provider.py
│   ├── audit/
│   │   ├── database.py
│   │   └── repository.py
│   └── static/
│       ├── index.html
│       ├── styles.css
│       └── app.js
├── tests/
│   ├── test_detector.py
│   ├── test_risk.py
│   ├── test_policies.py
│   ├── test_api.py
│   └── test_provider_safety.py
├── .env.example
├── .gitignore
├── requirements.txt
├── PRD.md
├── ARCHITECTURE.md
├── AGENTS.md
├── TASKS.md
├── CONTEXT.md
├── CHANGELOG.md
└── TESTING.md
```

## Local setup

1. Install Python 3.12 or 3.13.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

4. Copy `.env.example` to `.env` and configure values. Keep real API keys only in `.env`; never commit it.
5. Start the app:

```bash
uvicorn app.main:app --reload
```

6. Open `http://127.0.0.1:8000/docs`.

The exact commands may be adjusted for the final implementation and operating system.

## Development principles

- Keep trusted system instructions separate from untrusted content.
- Treat user text and retrieved content as data, not as instructions for the gateway.
- Never accept a client-supplied policy as authoritative when the server is configured to enforce its own policy.
- Do not log API keys, full sensitive documents, or unnecessary personal data.
- Use deterministic tests and mock the provider in automated tests.
- Make the reason for each decision inspectable.
- Fail closed for provider calls when a required security check or authorization step fails.

## Out of scope for the MVP

- Guaranteed detection of every prompt injection.
- Autonomous tool execution or agent permissions.
- Parsing every PDF, email, or webpage format. The MVP accepts extracted text; extraction can be added later.
- Model training or a custom machine-learning classifier.
- Multi-tenant enterprise identity management.
- Production-grade high availability and distributed deployment.

## Documentation

- [Product requirements](PRD.md)
- [Architecture](ARCHITECTURE.md)
- [Agent/developer instructions](AGENTS.md)
- [Implementation tasks](TASKS.md)
- [Project context](CONTEXT.md)
- [Change history](CHANGELOG.md)
- [Testing plan](TESTING.md)
