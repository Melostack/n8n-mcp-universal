## 2024-05-08 - Weak random number generation for security purposes
**Vulnerability:** Weak random number generation for generating sensitive identifiers
**Learning:** Generating unique identifiers like session IDs using Math.random() is susceptible to prediction and collision attacks, leading to security flaws in session tracking
**Prevention:** Utilize cryptographically secure methods like crypto.randomBytes() or crypto.randomUUID() provided by Node.js for generating random identifiers.
