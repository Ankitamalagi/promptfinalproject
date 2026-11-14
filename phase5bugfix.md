I ran the complete test suite and got:

156 passed, 1 failed.

Failure:
tests/test_scan_api.py::TestChatEndpoint::test_valid_chat_request

Expected:
assert data["provider_called"] is False

Actual:
provider_called is True.

Please investigate this failure carefully.

1. Read the failing test and understand why it expects provider_called to be False.
2. Inspect the Phase 5 chat endpoint and provider integration.
3. Check whether the test reflects the old behaviour before Phase 5.
4. Check whether a valid ALLOW request is correctly supposed to call the configured provider.
5. Do not blindly change the test to make it pass.
6. Do not blindly change the application logic.
7. Make the smallest correct change based on the intended Phase 5 requirements.
8. Preserve all existing security rules:
   - ALLOW can call the provider.
   - SANITIZE can call the provider only with approved sanitized content.
   - FLAG must not call the provider.
   - BLOCK must not call the provider.
9. Run the complete test suite again.
10. Explain the root cause and every changed file in beginner-friendly English.

Do not start Phase 6.