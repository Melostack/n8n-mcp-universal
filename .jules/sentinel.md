## 2024-05-30 - Sentinel initialized\n**Learning:** Sentinel is active
## 2024-05-30 - Replace Math.random with Cryptographically Secure Random Generation
**Vulnerability:** Several utility functions generated unique identifiers (e.g., `sessionId`, `conditionId`, `nodeId`) using `Math.random()`, which is predictable and insecure for security-sensitive logic.
**Learning:** `Math.random` is an easy trap to fall into for ID generation, but in an integration context, predictable session IDs or identifiers can lead to spoofing or brute-force tracking risks.
**Prevention:** Always rely on Node's built-in `crypto` module (e.g., `crypto.randomBytes(n).toString('hex')` or `crypto.randomUUID()`) when generating any identifier or token meant to be unique and unpredictable.
