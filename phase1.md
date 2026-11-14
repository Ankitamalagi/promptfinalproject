Proceed with Phase 1 — Request Models and Input Handling, following TASKS.md, PRD.md, ARCHITECTURE.md, AGENTS.md and TESTING.md.

Important instructions:
1. First inspect the existing Phase 0 implementation.
2. Explain which files you will create or modify and why.
3. Implement only Phase 1. Do not start Phase 2.
4. Use Pydantic models and FastAPI validation.
5. Preserve original input separately from normalized input.
6. Add appropriate input length limits and source validation.
7. Write tests for valid, missing, malformed and oversized requests.
8. Run the complete test suite and fix any failures.
9. Update TASKS.md and CHANGELOG.md only after successful verification.
10. Explain every important file and implementation in simple English because I am a beginner.

Do not delete or rewrite working Phase 0 code unnecessarily. Stop after Phase 1 and show me the test results.
Proceed with Phase 2 — Prompt Detection and Security Analysis, following TASKS.md, PRD.md, ARCHITECTURE.md, AGENTS.md, CONTEXT.md and TESTING.md.

Act as a senior Python backend engineer and AI security engineer. Remember that I am a beginner, so explain the implementation in simple English.

Important instructions:

1. First inspect the completed Phase 1 implementation and existing tests.
2. Do not modify or break working Phase 1 functionality.
3. Explain the files you plan to create or modify before coding.
4. Implement only Phase 2. Do not start Phase 3.

Implement the following:

**A. Rule-based detection engine**
- Detect suspicious instruction patterns in user messages.
- Analyze retrieved document content separately from user messages.
- Identify instruction override attempts.
- Identify role manipulation attempts.
- Identify requests to expose sensitive information.
- Identify attempts to bypass security restrictions.
- Identify suspicious tool-manipulation instructions.
- Identify suspicious obfuscated text patterns where appropriate.

**B. Detection results**
For each detection, return:
- Detection category
- Risk indicator
- Short explanation
- Source of the suspicious content
- Matched rule identifier

**C. Security requirements**
- Treat retrieved content as untrusted data.
- Never execute instructions found in retrieved content.
- Do not treat ordinary educational discussions about security as attacks automatically.
- Keep detection rules modular and easy to extend.
- Avoid storing raw sensitive prompts in audit logs.
- Do not claim that rule-based detection catches every prompt injection.

**D. Testing**
Write unit tests for:
- Normal harmless messages.
- Suspicious direct user messages.
- Suspicious retrieved content.
- Multiple detection categories.
- Empty optional retrieved content.
- False-positive educational discussions.
- Malformed inputs.
- Case variations and whitespace variations.

Use safe synthetic test examples. Do not include operational attack instructions.

**E. Code quality**
- Follow the existing project structure.
- Use clear function and variable names.
- Add comments where necessary.
- Avoid unnecessary dependencies.
- Keep the detection engine separate from API routes.

**F. Verification**
- Run the complete test suite, including Phase 1 tests.
- Fix failures caused by Phase 2.
- Show the exact test results.
- Explain the detector with a simple example.
- Update TASKS.md and CHANGELOG.md only after successful verification.

Stop after Phase 2. Do not begin Phase 3 — Risk Scoring until I review and approve the implementation.
Proceed with Phase 3 — Risk Scoring Engine for my Prompt Injection Security Gateway.

Act as a senior Python backend engineer and AI security engineer. I am a beginner, so explain everything in simple English.

Follow README.md, PRD.md, ARCHITECTURE.md, AGENTS.md, CONTEXT.md, TASKS.md and TESTING.md.

IMPORTANT RULES:
1. Inspect the completed Phase 1 and Phase 2 code before implementation.
2. Do not break or unnecessarily rewrite existing functionality.
3. Explain the files you plan to create or modify.
4. Implement only Phase 3. Do not start Phase 4.
5. Follow the existing project architecture.

IMPLEMENT THE FOLLOWING:

A. Risk Scoring
- Convert Phase 2 detection results into a numerical risk score from 0 to 100.
- Use the risk weights defined in CONTEXT.md and PRD.md.
- Avoid double-counting duplicate detections.
- Ensure the final score never exceeds 100.
- Give a score of 0 when no suspicious indicators are detected.

B. Risk Categories
Use the documented thresholds:
- 0–29: LOW
- 30–59: MEDIUM
- 60–79: HIGH
- 80–100: CRITICAL

C. Risk Assessment Output
Return:
- Risk score
- Risk level
- Detected categories
- Short explanation
- Detection count

D. Security Requirements
- Do not treat the risk score as a probability.
- Do not allow user input to change scoring weights.
- Keep scoring logic separate from API routes.
- Handle empty detection results safely.
- Make scoring deterministic and testable.

E. TESTING
Write unit tests for:
- Zero detections.
- One low-risk detection.
- One high-risk detection.
- Multiple different detections.
- Duplicate detections.
- Maximum score of 100.
- Every risk-level boundary.
- Empty detection results.
- Invalid detection data.

F. VERIFICATION
- Run all Phase 1, Phase 2 and Phase 3 tests.
- Fix any failures caused by Phase 3.
- Show exact pytest results.
- Explain the scoring calculation using simple examples.
- Update TASKS.md and CHANGELOG.md only after successful verification.

Stop after Phase 3. Do not start Phase 4 until I approve it.
# PHASE 5 — LLM PROVIDER INTEGRATION

You are working on my college mini-project: **Prompt Injection Security Gateway for AI Applications**.

Phases 0–4 have already been implemented. Now implement ONLY Phase 5.

I am a beginner, so keep the code simple, modular, readable, and well-commented.

## 1. First inspect the existing project

Before making changes:

- Read README.md, PRD.md, ARCHITECTURE.md, TASKS.md, CONTEXT.md, AGENTS.md and TESTING.md.
- Inspect the implementations of Phases 1, 2, 3 and 4.
- Understand the existing request models, detector, risk scorer and policy engine.
- Identify how the current application handles requests.
- Do not rewrite or unnecessarily modify completed phases.

## 2. Implement LLM provider integration

Create a simple provider integration layer.

Requirements:

- Define a common provider interface.
- Implement an OpenAI provider using the official OpenAI Python SDK if it is already installed; otherwise add the appropriate dependency.
- Read the API key from an environment variable named OPENAI_API_KEY.
- Never hardcode API keys.
- Read the model name from configuration.
- Set a reasonable request timeout.
- Handle API errors, timeout errors and missing API keys safely.
- Never expose API keys in API responses or logs.

## 3. Connect the security policy engine

This is the most important requirement.

The request must follow this flow:

1. Receive the request.
2. Validate the input.
3. Detect suspicious instructions.
4. Calculate the risk score.
5. Apply the security policy.
6. Only then decide whether to call the AI provider.

Enforce these rules:

- ALLOW: Send the permitted message to the AI provider.
- SANITIZE: Send only the approved sanitized message to the AI provider.
- FLAG: Do not call the provider. Return a review-required response.
- BLOCK: Do not call the provider. Return a blocked response.

Never allow the frontend or client request to override the server-side security policy.

## 4. Create or update the chat API

Implement or update the existing chat endpoint, preferably `/api/chat`.

The response should clearly include:

- Request ID
- Policy decision
- Risk score
- Risk level
- Security findings
- Whether the AI provider was called
- AI response, if available
- A safe error message, if the provider fails

Do not expose internal secrets or sensitive configuration.

## 5. Add a demo mode

Create a DEMO provider so the project can be demonstrated without an OpenAI API key or paid API usage.

The demo provider should return a clearly labelled simulated AI response.

It must use the same policy checks as the real provider.

Do not pretend that a simulated response came from a real AI model.

## 6. Testing

Add automated tests for:

- ALLOW calls the provider.
- SANITIZE calls the provider with the sanitized message, not the original.
- FLAG does not call the provider.
- BLOCK does not call the provider.
- Missing API key is handled safely.
- Provider timeout is handled safely.
- Provider API errors are handled safely.
- Demo provider works without an API key.
- API response contains the correct policy and risk information.

Use a fake/mock provider for tests. Do not make real paid API calls during automated tests.

## 7. Documentation

Update TASKS.md and CHANGELOG.md only after successful implementation and testing.

Explain which files were created or modified and what each file does.

## 8. Important instructions

- Implement ONLY Phase 5.
- Follow the existing architecture.
- Do not build the dashboard yet.
- Do not add unrelated features.
- Do not remove existing tests.
- Do not store raw prompts in audit logs.
- Do not send requests to the provider when the decision is FLAG or BLOCK.
- Run the complete test suite.
- Fix any failures caused by Phase 5.
- Report the test results honestly.
- Stop after Phase 5 and wait for my confirmation before starting Phase 6.