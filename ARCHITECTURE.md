# System Architecture

## 1. Architectural style

The MVP uses a modular monolithic backend: one FastAPI service divided into clear modules. This is simpler to develop and demonstrate than microservices while keeping components replaceable.

The gateway sits between an AI application and an LLM provider:

```text
AI application / client
        |
        | HTTPS REST request
        v
+--------------------------------------+
| Prompt Injection Security Gateway    |
|                                      |
| API + request validation             |
|        |                             |
| Input/source manager                 |
|        |                             |
| Normalizer                            |
|        |                             |
| Rule-based detector                  |
|        |                             |
| Risk scorer (0-100)                  |
|        |                             |
| Policy engine                        |
|    |       |       |       |         |
|  ALLOW   FLAG    BLOCK  SANITIZE     |
|    |       |       |       |         |
|    |    hold      reject  transform  |
|    |                       + re-scan |
|    +---------------+-----------------+
|                    |
|              Provider adapter
|                    |
|              Audit repository
+--------------------+
        |                    |
        v                    v
   LLM provider          SQLite database
        |
        v
  Gateway response
        |
        v
  AI application
```

## 2. Trust boundaries

A trust boundary is a separation between data with different levels of trust.

- **Trusted application configuration:** server-owned system instructions, policy configuration, provider credentials.
- **Untrusted user input:** user messages and uploaded text.
- **Untrusted retrieved input:** webpages, PDFs, emails, search results, and other external content.
- **Provider output:** model-generated content; treat as untrusted output and validate before using it in sensitive operations.

The gateway should retain source labels. It must not combine untrusted content into a trusted system-instruction field.

## 3. Components

### API layer (`app/api`)
FastAPI routes, request/response schemas, validation, status codes, and dependency wiring.

### Input manager (`app/core` or `app/security`)
Accepts user text and retrieved text as separate fields. Enforces maximum sizes and source labels.

### Normalizer (`app/security/normalizer.py`)
Creates a predictable analysis representation. Preserve the original input; normalization must not silently change what is forwarded.

### Detector (`app/security/detector.py`)
Runs deterministic rules and returns findings:
- rule ID
- category
- source field
- severity/weight
- safe evidence snippet or offset

Do not treat a phrase match alone as proof of an attack.

### Risk scorer (`app/security/risk.py`)
Aggregates category contributions with caps and returns a score between 0 and 100 plus a breakdown. Repeated occurrences must not exceed the category cap.

### Policy engine (`app/security/policies.py`)
Applies server-side policy. It returns an explicit action and reason. `FLAG` means hold, not silently forward.

### Sanitizer (`app/security/sanitizer.py`)
Produces a separate candidate representation and transformation report. It must not overwrite the original. Re-scan the candidate. If safe transformation cannot be established, hold or block.

### Provider interface (`app/providers/base.py`)
Defines a common async interface so the rest of the gateway is not tied to one provider.

### OpenAI adapter (`app/providers/openai_provider.py`)
Calls the configured provider using HTTPX or an official client. Uses environment-based credentials, timeout, bounded retries where appropriate, and safe error handling. Never send a request when policy says hold or block.

### Audit (`app/audit`)
Stores timestamp, request ID, source labels, score, findings summary, policy, decision, and whether the provider was called. Do not store raw prompt text or secrets by default.

### Dashboard (`app/static`)
Displays aggregate audit information and recent events. Dashboard access must not expose provider credentials or unrestricted raw content.

## 4. Request and response data

Example request:

```json
{
  "request_id": "demo-001",
  "user_message": "Summarize the attached document.",
  "retrieved_content": "Document text extracted by the client...",
  "sources": ["user", "uploaded_pdf"]
}
```

Example scan response:

```json
{
  "request_id": "demo-001",
  "risk_score": 45,
  "risk_level": "medium",
  "findings": [
    {
      "rule_id": "PI-001",
      "category": "instruction_override",
      "source": "retrieved_content",
      "reason": "Possible attempt to override application instructions"
    }
  ],
  "policy": "FLAG",
  "decision": "held_for_review",
  "provider_called": false
}
```

These values are illustrative. Actual findings depend on detector rules.

## 5. Policy flow

```text
Validated request
      |
      v
Detect + score
      |
      v
Resolve server-side policy
      |
      +-- BLOCK --> reject; provider not called
      |
      +-- FLAG --> hold; require authorized approval
      |
      +-- SANITIZE --> transform candidate --> re-scan
      |                                  |
      |                                  +--> unresolved risk: hold/block
      |                                  +--> acceptable: provider adapter
      |
      +-- ALLOW --> provider adapter, subject to remaining checks
```

For an MVP without reviewer authentication, `FLAG` can return a held result and provide no automatic provider call. Approval can be simulated only in a clearly marked local demo, not exposed as an unauthenticated production action.

## 6. API design

- `POST /api/scan`: scan only; never calls provider.
- `POST /api/chat`: scan and conditionally call provider.
- `GET /api/config`: safe configuration metadata only.
- `GET /api/logs`: bounded, paginated audit metadata.
- `GET /api/health`: health check.

## 7. Data model

Suggested `audit_events` table:

| Column | Type | Notes |
|---|---|---|
| id | integer | Primary key |
| request_id | string | Correlation identifier |
| created_at | datetime | UTC timestamp |
| sources | string/JSON | Source labels only |
| risk_score | integer | 0–100 |
| risk_level | string | low/medium/high/critical |
| policy | string | server-applied policy |
| decision | string | allowed/held/rejected/sanitized |
| finding_codes | string/JSON | Rule IDs/categories |
| provider_called | boolean | Whether provider was invoked |
| provider_status | string | Optional status, no secret data |

## 8. Security controls

- Keep API credentials in environment variables; exclude `.env` from Git.
- Apply request size limits and input validation.
- Use server-side policy configuration; ignore or reject untrusted client policy overrides.
- Keep system instructions separate from user/retrieved content.
- Do not execute instructions found in retrieved text.
- Do not allow detector output to authorize tools or data access.
- Use timeouts and safe provider error handling.
- Do not log full prompts by default.
- Restrict dashboard and log access before deployment beyond localhost.
- Use HTTPS and authentication for any non-local deployment.

## 9. MVP limitations and future architecture

The MVP accepts extracted text rather than parsing arbitrary files itself. A future ingestion module may extract PDF/webpage/email text while preserving provenance and untrusted status. Future versions can add authenticated human review, rate limiting, provider adapters, and evaluation metrics.
