# Security Policy

**Project:** GBLOXKOS MORPHEUS V.1
**Maintainer:** GBLOXKOS LLC

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting a Vulnerability

If you discover a security issue, please report it privately to GBLOXKOS LLC
instead of opening a public issue. Include a description, affected endpoint or
file, and reproduction steps.

You can expect an acknowledgement within a few business days.

## Security Considerations for Operators

This dashboard renders third-party RSS and wiki content and interacts with a
local Ollama instance. Before deploying:

- **Enable API authentication** by setting the `API_TOKEN` environment variable.
  API routes then require a matching `X-API-Token` header.
- **Restrict CORS** with `ALLOW_CORS_ORIGINS` rather than leaving it open.
- **Terminate TLS** in front of the service (reverse proxy). The bundled server
  is Python's development server.
- **Keep the bind address local** unless you intend to expose it.
- **Audit regularly** with `python3 audit.py`, which validates security headers,
  CORS configuration, input validation, and token handling.
- **Keep dependencies current** with `pip install -r requirements.txt --upgrade`.

## Hardening Already Present

- Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and
  X-XSS-Protection headers are set on responses.
- Client-supplied system messages are rejected so untrusted input cannot override
  the authoritative server-side domain prompt.
- Fetched RSS and wiki content is sanitised before being served or injected into
  model prompts.
- Per-endpoint rate limiting protects abuse-prone routes.
