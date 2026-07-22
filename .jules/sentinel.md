## 2024-05-24 - [Avoid logging raw request body in HTTP Endpoints]
**Vulnerability:** Raw incoming JSON-RPC payloads (`req.body`, `bodyContent`) and request headers (`req.headers`) were being fully serialized and logged in the production logger, especially in the authentication wrapper.
**Learning:** This leads to credential leakage as Bearer tokens, JSON-RPC params containing sensitive tool information or other API keys could be present in the headers or the body content.
**Prevention:** Avoid logging complete `req.body` and `req.headers` objects, specifically within authentication routines or generic endpoints. When tracking request structure, log boolean indicator flags (`hasBody: !!req.body`, `hasHeaders: !!req.headers`) or only extract non-sensitive properties.
