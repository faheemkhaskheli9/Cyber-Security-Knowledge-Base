# AI & LLM Security

## What
Security of applications built on large language models (chatbots, RAG systems, coding assistants, autonomous agents with tools) and of the ML pipeline behind them (data, training, model files, serving). Also covers classic adversarial ML and using AI for defense.

Key idea: an LLM cannot reliably separate instructions from data. Anything it reads can steer it, and anything it outputs is untrusted.

## Why it matters
- Agents now hold credentials and can send email, run code, merge PRs and call APIs, so a single injected instruction can become a real action.
- RAG and tool use pull untrusted content (web pages, emails, tickets, docs) straight into the model's context.
- Model files are executable supply-chain artifacts (`pickle` runs code on load).
- Regulation is arriving: EU AI Act obligations phase in from 2025 (see `kb/09-governance/grc-compliance-privacy.md`).
- **Lethal trifecta**: an agent with access to private data + exposure to untrusted content + an outbound channel can be made to exfiltrate data. Remove at least one leg.

## Attacks
### OWASP Top 10 for LLM Applications (2025)
| ID | Risk | Example |
|----|------|---------|
| LLM01 | Prompt injection (direct and indirect) | User types "ignore previous instructions"; or a web page/email/PDF the model reads hides instructions (white text, HTML comments, image text) |
| LLM02 | Sensitive information disclosure | Model reveals PII, secrets in context, other tenants' data from shared RAG index |
| LLM03 | Supply chain | Malicious `pickle` model, backdoored fine-tune, compromised plugin/MCP server, typosquatted package |
| LLM04 | Data and model poisoning | Poisoned training/fine-tune data or RAG documents plant backdoors or false facts |
| LLM05 | Improper (insecure) output handling | Output rendered as HTML (XSS), passed to `eval`/shell (RCE), SQL (SQLi), or markdown image URL leaking data |
| LLM06 | Excessive agency | Agent has delete/send/pay tools, broad scopes, and no approval step |
| LLM07 | System prompt leakage | Secrets, internal rules or API keys placed in the system prompt get extracted |
| LLM08 | Vector and embedding weaknesses | No per-user access control in vector DB, embedding inversion, poisoned documents ranking first |
| LLM09 | Misinformation (overreliance) | Hallucinated packages ("slopsquatting"), wrong code or legal claims trusted without review |
| LLM10 | Unbounded consumption | Model DoS, cost exhaustion ("denial of wallet"), model extraction via mass queries |

Earlier (2023, v1.1) list items still worth knowing: training data poisoning, model DoS, insecure plugin/tool design, overreliance, model theft.

### Agent / MCP specific
- **Tool poisoning**: malicious instructions inside an MCP tool description or tool result.
- **Rug pull**: a trusted server silently changes tool definitions after approval.
- **Confused deputy / token passthrough**: server reuses the user's token against other APIs with more privilege than intended.
- **Cross-tool exfiltration**: injected content makes the agent call a "fetch URL" or "send email" tool with private data.
- **Auto-run code**: agent executes generated shell commands on a developer's workstation.

### Adversarial ML
Evasion (adversarial examples), poisoning, model inversion, membership inference, model extraction/theft, jailbreaks of safety training.

## Defenses
### Design rules
1. Treat all model input AND output as untrusted; never execute output without validation/sandboxing.
2. Least privilege for tools/agents: narrow tool set, read-only by default, scoped short-lived credentials per user/session (never a shared admin key).
3. Human-in-the-loop for destructive or outward actions (delete, send, pay, merge, deploy); show the exact action and parameters for approval.
4. Content isolation: separate trusted instructions from untrusted content (web pages, emails, docs may contain hidden instructions). Mark/quote untrusted data, use a privileged/quarantined LLM split, and never let retrieved text change tool permissions.
5. Output handling: encode for the sink (HTML-escape, parameterized SQL, no `eval`), strict schemas (JSON schema validation), allowlist URLs, block markdown images to external domains. See `kb/03-application/owasp-top10.md`.
6. Sandboxing: run generated code in ephemeral containers/VMs with no credentials and no network by default (`kb/04-cloud-infra/containers-kubernetes-iac.md`).
7. Egress controls to limit data exfiltration; no secrets in prompts or system prompts (`kb/05-identity-crypto/secrets-management.md`).
8. RAG access control: enforce the user's permissions at retrieval time (filter by ACL metadata), separate indexes per tenant, sanitize ingested documents.
9. Rate limits and quotas per user/key; cap tokens, tool-call depth, loop iterations and spend; alert on cost spikes.
10. Log and monitor tool calls, prompts and outputs (with PII redaction); feed to the SIEM (`kb/08-defensive/soc-detection-ir.md`).

### Supply chain
- Verify model/dataset provenance (hashes, signed artifacts); avoid `pickle` model files (use safetensors).
- Scan models (ModelScan, picklescan); pin model versions and revisions; keep an AI-BOM.
- Load with safe options (e.g. `torch.load(..., weights_only=True)`); never `trust_remote_code=True` on unreviewed repos.

### MCP / agent hardening
- Install MCP servers only from trusted sources; pin versions; review tool descriptions; alert on definition changes.
- Run local servers with minimal filesystem/network access; use OAuth with audience-bound tokens (the MCP spec forbids token passthrough).
- Per-tool allowlists and approval policies; separate agents for "reads untrusted content" vs "has sensitive tools".

### Testing and governance
- Red-team: Garak, PyRIT, promptfoo. Build an eval suite of injection, jailbreak, leakage and tool-misuse cases; run it in CI on every prompt/model change.
- Frameworks: MITRE ATLAS (adversary tactics), NIST AI RMF (Govern/Map/Measure/Manage) with NIST AI 600-1 Generative AI Profile, ISO/IEC 42001 (AI management system), OWASP AI Exchange.
- Threat-model each AI feature (`kb/01-foundations/threat-modeling.md`): data sources, tools, trust boundaries, blast radius.

### AI for defense
Triage assistance, log summarization, code review, detection drafting — always verify output. Do not paste secrets or customer data into unapproved AI tools.

## How to verify
- Indirect injection test: place a hidden instruction in a document/web page the app ingests; confirm no tool call or data leak follows.
- Ask for the system prompt; confirm nothing sensitive is in it even if extracted.
- Output sink test: make the model emit `<script>`, a markdown image to an external URL, and SQL/shell metacharacters; confirm they are encoded or blocked.
- RAG ACL test: user A cannot retrieve user B's documents.
- Review agent tool inventory: every write/outward tool requires approval; credentials are scoped and short-lived.
- Scan model artifacts: `modelscan -p ./models`; confirm no `.pkl`/`.bin` pickles from untrusted sources.
- Run `garak` / `promptfoo` red-team suites; track pass rate over time.
- Confirm rate limits and spend alerts fire under load.

## References
- OWASP GenAI Security Project (Top 10 for LLM Applications 2025): https://genai.owasp.org
- OWASP AI Exchange: https://owaspai.org
- MITRE ATLAS: https://atlas.mitre.org
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework · NIST AI 600-1 (Generative AI Profile)
- ISO/IEC 42001:2023 (AI management systems)
- Model Context Protocol (security best practices in spec): https://modelcontextprotocol.io
- Tools: garak (NVIDIA), PyRIT (Microsoft), promptfoo, ModelScan (Protect AI), safetensors
- See also `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/03-application/api-security.md`
