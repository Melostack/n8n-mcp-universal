## 2024-05-18 - Fix weak random number generation for security purposes in sessionId
**Vulnerability:** Using Math.random() (a cryptographically weak pseudo-random number generator) to create session identifiers.
**Learning:** This issue exists across various parts of the codebase. It represents a potential security risk since session ids generated using Math.random() can be guessable.
**Prevention:** Use `crypto.randomBytes(n).toString('hex')` to generate random hex strings of a specific length, choose `n` efficiently to closely match the desired output length.
