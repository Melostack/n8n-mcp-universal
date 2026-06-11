## 2024-05-27 - [Replace insecure random generation]
**Vulnerability:** Weak random number generation using `Math.random()` to generate unique identifiers (like node IDs, condition IDs, session IDs). Predictable PRNGs can be exploited if predictability affects security logic.
**Learning:** `Math.random()` was spread across multiple files. It's important to standardize on `crypto.randomBytes(5).toString('hex')` to safely mock output length and retain cryptographic security.
**Prevention:** Avoid `Math.random()` entirely for generating session IDs, identifiers, or tokens. Always rely on Node.js `crypto` (e.g., `crypto.randomBytes()` or `crypto.randomUUID()`).
