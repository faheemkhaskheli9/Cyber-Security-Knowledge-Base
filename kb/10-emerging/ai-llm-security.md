# AI & LLM Security

**OWASP Top 10 for LLM Apps**: Prompt injection (direct/indirect), insecure output handling, training data poisoning, model DoS, supply-chain (models/plugins), sensitive info disclosure, insecure plugin/tool design, excessive agency, overreliance, model theft.

## Defenses for LLM/agent apps
- Treat all model input AND output as untrusted; never execute output without validation/sandboxing.
- Least privilege for tools/agents; human approval for destructive/outward actions; scoped short-lived credentials.
- Separate trusted instructions from untrusted content (web pages, emails, docs may contain hidden instructions).
- Egress controls to limit data exfiltration; no secrets in prompts; log and monitor tool calls.
- Verify model/dataset provenance (hashes, signed artifacts); avoid `pickle` model files (use safetensors).
- Red-team: Garak, PyRIT, promptfoo. Frameworks: MITRE ATLAS, NIST AI RMF, OWASP AI Exchange.
- Adversarial ML: evasion, poisoning, model inversion, membership inference, extraction.

## AI for defense
Triage assistance, log summarization, code review, detection drafting — always verify output.
