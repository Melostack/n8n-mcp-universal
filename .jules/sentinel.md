## 2026-07-27 - [Express Rate Limit Configuration]
**Vulnerability:** In Express endpoints protected by `express-rate-limit`, failing to set `skipSuccessfulRequests: true` on authentication endpoints allows legitimate requests to consume the rate limit window, potentially locking out valid users if the threshold is reached or during periods of high legitimate traffic.
**Learning:** Rate limiters applied specifically for authentication failures should exclusively count failed attempts.
**Prevention:** Ensure `skipSuccessfulRequests: true` is configured for authentication rate limiters to prevent DoS by legitimate traffic exhaustion.
