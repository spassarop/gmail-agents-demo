# SECURITY_NOTES (What the patched version is doing)

This demo maps directly to OWASP ASI01 (Agent Goal Hijack) mitigations:
- Treat all natural-language inputs as untrusted
- Validate agent intent at runtime before executing high-impact actions
- Require human approval for risky actions
- Maintain comprehensive logs and monitoring

Patched defenses implemented here:
1) **Structured Tool Invocation** (JSON + Pydantic schemas)
2) **Intent Gate middleware** (policy checks on every tool call)
3) **Human-in-the-Loop** (sending email requires explicit confirmation in the UI)

This is intentionally a minimal educational reference implementation; real systems should add:
- stronger prompt injection classifiers
- allowlists for external recipients/domains
- per-user/session scoping and least privilege
- rate limits and anomaly detection
