## 2026-08-09 - [Replace Math.random with crypto.randomBytes]
**Vulnerability:** Use of predictable pseudo-random number generator Math.random() for security-adjacent purposes like session IDs and token generation.
**Learning:** Math.random() should not be used for cryptographic purposes.
**Prevention:** Always use the built-in Node.js crypto module (e.g., crypto.randomBytes()) for cryptographically secure random generation.
