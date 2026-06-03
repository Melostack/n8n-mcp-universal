## 2025-02-18 - [Weak Randomness for Session IDs]
**Vulnerability:** Found insecure `Math.random()` being used to generate session/mutation IDs and API identifiers.
**Learning:** Standard PRNGs are not cryptographically secure, and using them for any IDs that track state or represent objects poses a collision or predictability risk.
**Prevention:** Always use Node.js `crypto` module (e.g. `crypto.randomBytes`) or `crypto.randomUUID()` when generating tokens, identifiers, or session names.
