# Testing Strategy and Test Plan

## 1. Purpose

Testing verifies that the gateway behaves as designed, especially that untrusted content is inspected and that requests marked for hold or rejection do not reach the LLM provider.

The detector is heuristic. Tests demonstrate expected behaviour for known cases; they do not prove that all prompt injections can be detected.

## 2. Test levels

### Unit tests
Test individual functions without starting the API:
- normalization
- detector rules
- risk score calculation
- policy decisions
- sanitizer transformation and re-scan behaviour

### API tests
Use FastAPI's test client to verify request validation, status codes, and response schemas.

### Integration tests
Use a fake provider and temporary SQLite database to test the complete request flow without network access.

### Manual demonstration
Use Swagger UI or the dashboard to submit benign, direct-injection, and indirect-injection examples.

## 3. Test environment

- Python 3.12 or 3.13
- Pytest
- FastAPI TestClient / HTTPX
- Temporary SQLite database
- Fake provider
- No real API key required for automated tests

Run tests:

```bash
pytest -q
```

## 4. Detector test categories

| Case | Input shape | Expected result |
|---|---|---|
| D-01 | Ordinary question about Java arrays | No high-risk finding |
| D-02 | User text attempts to override earlier instructions | Override indicator may be raised |
| D-03 | Retrieved webpage text contains instruction-like content | Finding identifies `retrieved_content` as source |
| D-04 | Text asks for protected application secrets | Data-extraction indicator may be raised |
| D-05 | Harmless educational discussion mentioning prompt injection | Should not automatically be treated as a confirmed attack |
| D-06 | Empty or whitespace-only input | Validation or documented empty-input result |
| D-07 | Very long input | Rejected by size validation |
| D-08 | Repeated matching text | Score remains within category cap and 0–100 |

Use harmless, synthetic test strings. Do not include real credentials, private data, or harmful operational instructions.

## 5. Risk-scoring tests

- Empty findings produce score 0.
- Score is always an integer between 0 and 100.
- Each category contribution respects its configured cap.
- Total score never exceeds 100.
- Threshold boundaries map correctly to risk levels.
- Identical findings produce deterministic scores.
- Response includes a score breakdown and rule identifiers.

## 6. Policy tests

| Policy | Expected behaviour | Provider call |
|---|---|---|
| ALLOW | Request proceeds after checks | Yes, if provider enabled |
| FLAG | Request is held for review | No |
| BLOCK | Request is rejected | No |
| SANITIZE | Candidate is transformed and re-scanned | Only if re-check permits |

Additional checks:
- Client cannot override server policy.
- Sanitizer preserves original input separately.
- Sanitizer does not claim that content is safe merely because a phrase was removed.
- If re-scan fails or uncertainty remains, request is held or blocked.
- Scan-only endpoint never invokes provider.

## 7. Provider safety tests

Use a fake provider with a call counter.

Critical assertions:
- BLOCK: provider call count remains zero.
- FLAG: provider call count remains zero.
- SANITIZE with unresolved findings: provider call count remains zero.
- ALLOW: provider is called once when enabled.
- Sanitized and re-approved request: only the sanitized candidate is sent.
- Provider timeout: API returns a controlled error; no secret or traceback is exposed.
- Missing provider credentials: service remains usable for scanning; chat returns a clear provider-unavailable response.

## 8. Audit and privacy tests

- Audit event is written for each completed scan/chat decision.
- Audit event includes request ID, timestamp, source labels, score, policy, decision, and provider-call status.
- Raw prompt content is not stored by default.
- API keys and authorization headers never appear in logs or API responses.
- `/api/config` never returns secret values.
- `/api/logs` enforces a maximum page size.

## 9. API validation tests

- Valid request returns expected response fields.
- Missing required field returns 422.
- Invalid source label is rejected or normalized according to documented schema.
- Oversized request is rejected.
- Unknown policy supplied by client is rejected or ignored; server policy remains authoritative.
- Health endpoint returns success.
- Logs endpoint supports pagination safely.

## 10. Acceptance checklist

- [ ] Unit tests pass.
- [ ] API tests pass.
- [ ] Direct-injection examples are covered.
- [ ] Indirect-injection examples are covered.
- [ ] Benign false-positive examples are covered.
- [ ] Risk score boundaries are covered.
- [ ] All four policies are tested.
- [ ] BLOCK and FLAG provider-call count is zero.
- [ ] Sanitized content is re-scanned.
- [ ] Audit records do not contain raw prompts or secrets.
- [ ] Scan API works without an LLM provider.
- [ ] Manual demo can be repeated from a clean local setup.

## 11. Reporting test results

For each test run, record:
- Date and Python version.
- Command executed.
- Number of tests passed/failed.
- Failed test names and short explanation.
- Fix or follow-up task.

Never report tests as passed unless the command was actually run.
