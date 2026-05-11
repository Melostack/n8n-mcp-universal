## 2024-05-24 - Cryptographically Weak Random Generation for Session IDs
**Vulnerability:** Found `Math.random()` being used to generate random session IDs in `chat-handler.ts`, `handlers-n8n-manager.ts` and `handlers-workflow-diff.ts`. This makes session IDs predictable.
**Learning:** Node's `Math.random` is an insecure pseudo-random generator, predictable and thus insecure to be used as random identifiers that might be used for sessions, mutability tokens or any identifying tokens.
**Prevention:** Use `crypto.randomBytes(n).toString('hex')` or `crypto.randomUUID()` when generating security-sensitive random IDs, such as identifiers, session tokens, or node IDs.
