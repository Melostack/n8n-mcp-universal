## 2025-05-25 - [Medium] Replace insecure Math.random() with crypto
**Vulnerability:** The codebase was relying on the insecure `Math.random()` function to generate sensitive identifiers such as session IDs (e.g., `chat-handler.ts`, `handlers-n8n-manager.ts`) and condition/node IDs.
**Learning:** `Math.random()` does not produce cryptographically secure random numbers, making identifiers predictable. This could lead to collision issues or enumeration attacks in environments needing high assurance.
**Prevention:** Always utilize the `crypto` module built into Node.js (e.g., `crypto.randomBytes(5).toString('hex')` or `crypto.randomUUID()`) when generating unique or security-sensitive identifiers.
