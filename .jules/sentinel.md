## 2025-03-25 - [Missing rate limit on MCP auth]
**Vulnerability:** Missing rate limit on `/mcp` POST endpoints within `src/http-server.ts`.
**Learning:** Security updates made to one implementation/handler of an endpoint might be skipped on older or alternative legacy variants. `authLimiter` was present in `src/http-server-single-session.ts` but absent in the deprecated `src/http-server.ts` creating an attack vector for brute force and DoS via a legacy file/path.
**Prevention:** Always verify symmetric application of security updates across both current and legacy/deprecated routing or server files. Check implementations of same or similar endpoints codebase wide.
