## 2024-05-18 - Insecure Random Number Generation

**Vulnerability:** Weak random number generation using `Math.random()` to generate IDs for potentially sensitive tracking elements like session identifiers, execution variables, mutation signatures, and condition IDs.
**Learning:** Node's `Math.random()` provides pseudorandom sequences not suitable for secure or unique generation contexts since sequence continuation could theoretically be predicted, resulting in potentially guessable session identifiers and condition IDs.
**Prevention:** Always use Node.js's built-in `crypto` module (e.g., `crypto.randomUUID()` or `crypto.randomBytes()`) for generating unique identifiers where security and unpredictability are desired. `crypto.randomBytes(n).toString('hex')` should be efficiently used matching length with entropy desired.
