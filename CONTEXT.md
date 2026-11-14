# Project Context

## 1. Project identity

- **Title:** Prompt Injection Security Gateway for AI Applications
- **Type:** College mini-project / defensive AI-security middleware
- **Release target:** MVP 0.1
- **Primary language:** Python
- **Backend:** FastAPI
- **Initial database:** SQLite
- **Initial provider:** Optional OpenAI integration
- **Frontend:** HTML, CSS, JavaScript

## 2. Problem to solve

LLM applications may place system instructions, user messages, and retrieved documents into a shared prompt without sufficiently preserving trust boundaries. This creates opportunities for:

- **Direct prompt injection:** malicious instructions supplied directly in a user message.
- **Indirect prompt injection:** malicious instructions embedded in external content that an application retrieves or processes, such as a webpage, PDF, or email.

The project adds a reusable gateway that analyzes untrusted content, assigns a risk score, applies a handling policy, optionally forwards approved content to an LLM, and records an audit event.

## 3. Important vocabulary

| Term | Beginner-friendly meaning |
|---|---|
| LLM | AI model that understands and generates language |
| Prompt | Text and structured messages sent to an LLM |
| Prompt injection | Untrusted text attempting to influence an LLM's instructions or behaviour |
| Direct injection | Injection delivered in the user's own input |
| Indirect injection | Injection delivered through content the application retrieves |
| Gateway | Intermediate service that checks requests before forwarding them |
| REST API | Standard HTTP interface for software applications to communicate |
| FastAPI | Python framework for building APIs |
| Pydantic | Python library for validating data |
| Risk score | Heuristic number representing suspicious indicators, not attack probability |
| Sanitization | Transforming content to reduce or isolate suspicious material |
| Audit event | A record of a security decision |
| Provider adapter | A module that connects the gateway to a particular LLM service |

## 4. Agreed design decisions

1. Build a modular monolith rather than microservices.
2. Use Python and FastAPI.
3. Start with deterministic, explainable rules; no ML classifier in the first version.
4. Keep user messages and retrieved content in separate fields.
5. Use a 0–100 heuristic score with category caps.
6. Support ALLOW, FLAG, BLOCK, and SANITIZE.
7. Enforce policy on the server, not from client input.
8. Make `/api/scan` independent of any LLM provider.
9. Use a fake provider for offline tests and demos.
10. Add OpenAI as the first optional real provider.
11. Use SQLite for minimal audit metadata.
12. Avoid storing raw prompts and secrets in logs.
13. Accept extracted text in the MVP; file parsing is a future enhancement.

## 5. Initial risk categories

| Category | Maximum points |
|---|---:|
| Instruction override | 25 |
| Sensitive-data extraction attempt | 25 |
| Role/tool manipulation | 20 |
| Obfuscation | 10 |
| Suspicious instruction in external content | 10 |
| Security bypass | 10 |
| **Total** | **100** |

Proposed display levels:
- 0–29: low
- 30–59: medium
- 60–79: high
- 80–100: critical

Weights and thresholds are starting assumptions to evaluate against a test corpus. They are not validated probabilities.

## 6. Policy meanings

- **ALLOW:** Permit processing after checks.
- **FLAG:** Hold for authorized review; no automatic provider call.
- **BLOCK:** Reject; no provider call.
- **SANITIZE:** Produce a separate candidate, re-scan it, and forward only if the remaining checks permit it.

## 7. Constraints

- College MVP with limited development time.
- Beginner-friendly implementation and documentation.
- Must run locally on a Windows development machine as well as common Python environments.
- No dependency on a paid LLM for detector tests.
- No claim of complete prompt-injection prevention.
- Protect API credentials and avoid sensitive audit data.

## 8. Current status

This document describes the intended MVP baseline. Update this section as implementation progresses:
- Current phase: Design / planning.
- Implemented features: None confirmed by this document.
- Next task: Phase 0, repository and environment setup in `TASKS.md`.

## 9. How to use this context

When continuing development, read this file together with `PRD.md`, `ARCHITECTURE.md`, `AGENTS.md`, `TASKS.md`, and `TESTING.md`. If implementation differs from the design, update the documents rather than assuming the design is already implemented.
