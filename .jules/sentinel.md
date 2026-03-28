## 2025-03-09 - Remove hardcoded Supabase telemetry keys
**Vulnerability:** Telemetry backend URL and API key were hardcoded in the codebase, leading to potential abuse and uncontrolled access to the backend data if exposed.
**Learning:** Hardcoded credentials even for anonymized or basic telemetry backend is a critical security vulnerability and shouldn't be relied on for "zero-configuration". Proper environment variable configuration provides necessary isolation.
**Prevention:** Always enforce that connections or telemetry destinations are set entirely through environment variables rather than fallback constants. Use `.env.example` to guide user configurations instead.
