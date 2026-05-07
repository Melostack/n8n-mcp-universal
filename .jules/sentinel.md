## 2024-05-24 - [Insecure Randomness for Security IDs]
**Vulnerability:** The application used `Math.random().toString(36).substring(...)` to generate session IDs, mutation IDs, and node IDs. This weak pseudo-random number generator is predictable and not cryptographically secure, allowing potential guessing attacks on sensitive identifiers.
**Learning:** `Math.random()` should never be used for security-sensitive logic like unique identifiers, session tokens, or node IDs.
**Prevention:** Always use the built-in Node.js `crypto` module (e.g., `crypto.randomUUID()` or `crypto.randomBytes(5).toString('hex')`) for cryptographically secure random generation. Import it with `import crypto from 'crypto';` rather than using `require`.
