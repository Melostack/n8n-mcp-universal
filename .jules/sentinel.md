## 2024-05-24 - [Remove Hardcoded Credentials from Telemetry]
 **Vulnerability:** The `src/telemetry/telemetry-types.ts` file contained hardcoded production Supabase URL and Anon Key credentials. If exposed, these could be used to insert arbitrary data or exhaust telemetry rate limits/quotas.
 **Learning:** Centralized config/type files (`*-types.ts`, `constants.ts`) are common hiding spots for fallback credentials meant to enable "zero-configuration" setups, bypassing standard environment variable protections.
 **Prevention:** Ensure all external API clients strictly require environment variables for initialization and gracefully disable features if credentials are missing, rather than relying on hardcoded defaults.
