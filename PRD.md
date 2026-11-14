# Product Requirements Document (PRD)

## 1. Product overview

**Product:** Prompt Injection Security Gateway for AI Applications  
**Release:** College MVP, version 0.1  
**Primary users:** Developers building LLM-powered applications  
**Primary purpose:** Provide a reusable application-layer checkpoint that analyzes untrusted text before it is sent to an LLM provider.

## 2. Problem statement

Many LLM applications combine system instructions, user messages, and retrieved content without consistently maintaining trust boundaries. Malicious instructions may be submitted directly by a user (direct prompt injection) or embedded in external content such as webpages, PDFs, and emails (indirect prompt injection).

Provider-level safety features are useful but do not replace application-specific controls. Developers need a reusable layer for source-aware inspection, policy decisions, provider routing, and auditability.

## 3. Goals

1. Provide one central API for inspecting content from multiple AI applications.
2. Identify explainable suspicious indicators in user and retrieved text.
3. Produce a risk score from 0 to 100 with evidence.
4. Support four handling policies: Allow, Flag, Block, Sanitize.
5. Prevent blocked or held requests from reaching the LLM provider.
6. Integrate with one LLM provider through a replaceable adapter.
7. Record privacy-conscious security audit events.
8. Offer a basic dashboard and API documentation.

## 4. Non-goals

- Perfect or guaranteed prompt-injection prevention.
- Replacing provider safety systems.
- Treating a risk score as a probability of attack.
- Securely authorizing tools or business transactions.
- Automatically parsing all document formats in version 0.1.
- Building a custom model or training pipeline.
- Production-scale multi-region deployment.

## 5. Users and use cases

### Developer
A developer integrates the gateway into a chatbot or document assistant using REST APIs.

### Application operator
An operator views request counts, policy decisions, risk levels, and audit events.

### Demonstration user
A student or evaluator submits benign and suspicious sample inputs to observe decisions.

## 6. Functional requirements

| ID | Requirement | Acceptance condition |
|---|---|---|
| FR-01 | Accept text and source metadata | Valid request is parsed; invalid request receives a clear 4xx response |
| FR-02 | Support user and external content | Request can distinguish `user_message` from `retrieved_content` |
| FR-03 | Normalize input | Detector receives a predictable representation; original is not silently overwritten |
| FR-04 | Detect suspicious indicators | Detector returns rule IDs, categories, and matched evidence safely |
| FR-05 | Calculate risk | Score is an integer from 0 through 100 with a breakdown |
| FR-06 | Apply policies | Allow, Flag, Block, and Sanitize have distinct documented behaviours |
| FR-07 | Scan endpoint | `/api/scan` returns a decision without provider invocation |
| FR-08 | Chat endpoint | `/api/chat` invokes provider only for permitted requests |
| FR-09 | Provider abstraction | Provider can be replaced without changing detector or policy logic |
| FR-10 | Audit events | Decision, score, source, policy, timestamp, and provider-call status are recorded |
| FR-11 | Configuration endpoint | `/api/config` exposes safe, non-secret settings only |
| FR-12 | Logs endpoint | `/api/logs` supports bounded pagination and does not expose secrets |
| FR-13 | Health endpoint | `/api/health` reports service health |
| FR-14 | Dashboard | Shows summary counts and recent audit events |

## 7. Policy requirements

Policy selection is server-controlled. A public client must not be able to lower the server's protection level by sending its own policy value.

- **ALLOW:** Pass content onward after inspection, subject to application authorization and provider checks.
- **FLAG:** Hold the request for review; do not call the provider until an authorized reviewer approves it. Manual review UI may be simplified in the MVP.
- **BLOCK:** Reject the request; provider must not be called.
- **SANITIZE:** Create a transformed representation that isolates or removes identified untrusted instruction-like segments, retain a record of the transformation, then re-evaluate it before forwarding. If safe transformation is uncertain, hold or block rather than assume it is safe.

Policies are handling modes, not just score labels. The implementation must document how policy configuration and risk thresholds interact.

## 8. Risk scoring requirements

The score is a heuristic indicator, not a calibrated probability.

Initial proposed indicator weights (maximum contribution per category):

| Indicator category | Maximum |
|---|---:|
| Instruction override attempt | 25 |
| Sensitive-data extraction attempt | 25 |
| Role/tool manipulation | 20 |
| Obfuscation indicator | 10 |
| Suspicious instruction in external content | 10 |
| Security-control bypass attempt | 10 |
| **Maximum** | **100** |

The implementation must avoid blindly adding repeated matches beyond a category cap. It must return a score breakdown and detector rule IDs. Thresholds proposed for display: 0–29 low, 30–59 medium, 60–79 high, 80–100 critical. These thresholds must be configurable and tested.

## 9. API requirements

### `POST /api/scan`
Input: user message, optional retrieved content, source labels, and request ID.  
Output: score, risk level, indicators, policy, decision, sanitized preview if applicable, and provider-called status (`false`).

### `POST /api/chat`
Input: same security input plus application task/question.  
Output: security decision and, only when permitted, provider response.

### `GET /api/config`
Output: active server policy, thresholds, provider name, and whether provider integration is enabled. Never return API keys or secrets.

### `GET /api/logs`
Output: paginated audit metadata with limits on page size.

### `GET /api/health`
Output: basic service status.

## 10. Non-functional requirements

- **Explainability:** Every positive detection has a rule ID and human-readable reason.
- **Security:** Secrets are environment-configured; input size and request limits are enforced; errors do not leak secrets.
- **Privacy:** Avoid storing raw prompts by default. Prefer hashes, lengths, source labels, scores, and decision metadata.
- **Reliability:** Provider timeouts and failures are handled safely.
- **Maintainability:** Detection, scoring, policies, providers, API, and audit logic are separate modules.
- **Testability:** Core logic runs without network access using unit tests and mocked providers.
- **Usability:** Swagger UI and a simple dashboard are available.

## 11. Success criteria

The MVP is considered demonstrable when:
- Normal sample text receives a low-risk decision.
- Direct-injection test cases trigger relevant detector rules.
- Indirect-injection test cases are detected when included as retrieved content.
- All four policies behave as documented.
- A blocked request produces zero provider calls.
- A flagged request remains held until approval.
- Sanitized content is re-scanned before provider use.
- Audit records are created without storing secrets.
- API and automated tests pass.

## 12. Risks and mitigations

| Risk | Mitigation |
|---|---|
| False positives | Explain rules; tune thresholds using a labelled test corpus |
| False negatives | State limitations; add layered controls and regression cases |
| Sanitizer removes useful text | Preserve original separately; show transformation; re-scan |
| Client bypasses policy | Enforce policy on server side |
| Secrets leak in logs | Redact and avoid raw content storage |
| Provider unavailable | Timeout, safe error response, no unsafe fallback |
| Untrusted text imitates system messages | Keep trusted instructions in separate provider message fields; never promote retrieved text to system role |

## 13. Future enhancements

- PDF and webpage text extraction with safe parsing.
- More providers, such as Gemini or other supported APIs.
- Human-review queue and reviewer authentication.
- Detection evaluation dataset and precision/recall reporting.
- Rate limiting, API keys, role-based access control.
- Optional classifier as a supplementary signal, not sole authority.
