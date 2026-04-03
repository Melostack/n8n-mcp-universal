## 2025-04-03 - Math.random used for identifiers
**Vulnerability:** Weak PRNG `Math.random()` was used to generate pseudo-random identifiers like sessionId, mutationId, conditionId, and keys.
**Learning:** `Math.random()` does not produce cryptographically secure randomness, leaving IDs predictable.
**Prevention:** Use Node.js built-in `crypto` module methods like `crypto.randomBytes(n).toString('hex')` or `crypto.randomUUID()` when generating tokens, identifiers, or other values needing entropy.
