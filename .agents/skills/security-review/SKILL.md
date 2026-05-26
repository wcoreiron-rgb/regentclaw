---
name: security-review
description: Review changes for policy bypass, secrets exposure, and tenant isolation risk.
---

Check for:
1. Auth bypass or missing authorization checks.
2. Trust Fabric policy bypass paths.
3. Unsafe logging of secrets, prompts, credentials, or tenant data.
4. Missing validation/sanitization on user-controlled inputs.
5. Cross-tenant data leakage risks.
6. Unsafe connector/model actions without approval gates.

Output:
- must-fix findings
- should-fix findings
- residual risk + test gaps

