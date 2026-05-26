---
name: test-backfill
description: Add focused tests without changing production behavior.
---

1. Identify affected behavior and existing test style.
2. Add happy-path and failure-path tests for the targeted logic.
3. Do not alter production code unless explicitly requested.
4. If behavior appears incorrect, stop and report before changing tests.
5. Run only relevant test targets first, then broader suite when needed.

