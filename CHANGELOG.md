# Changelog

## [1.0.0] - 2026-10-11

First release - port of the AI Compliance Engine of Synthelion 1.2.5 to .NET.

- Rule registry (19 controls: risk, action, scope), per-rule overrides and administrator custom rules.
- Engine states (active / staging / inactive) and fallback policy (fail-closed for security and privacy, fail-open, warn-and-pass).
- Backends: Caveman.PrivacyGuard (PII, prompt injection), secrets scanner, agent-policy packs (gate / block), destructive commands, toxicity, illegal activity, PHI, data residency, code vulnerabilities, copyright, grounding, AI marking, output sanitiser, RAG provenance.
- Traceability matrix and coverage gaps from the live configuration; backend-health report for controls enabled but not operational.
- Hash-chained audit trail (Art. 12) with VerifyChain, statistics and conformity receipts; system-instruction version registry.
- Technical file, DPIA, FRIA and executive report as JSON and PDF (Stilo.Documents).
