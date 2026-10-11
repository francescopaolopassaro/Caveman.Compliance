<p align="center"><img src="https://raw.githubusercontent.com/francescopaolopassaro/caveman/main/caveman-icon.png" width="96" alt="Caveman"/></p>

# Caveman.Compliance

**An AI compliance gate for LLM applications.** One rule registry over every guard Caveman has - PII, secrets, prompt injection, agent policy, toxicity, health data, data residency, code vulnerabilities - a **traceability matrix** from each control to the article of law it satisfies, a **tamper-evident audit trail**, and the documents a compliance function actually asks for - **technical file, DPIA, FRIA and executive report** - generated as JSON *and* as PDF.

```
dotnet add package Caveman.Compliance
```

Part of the [Caveman](https://github.com/francescopaolopassaro/caveman) family. Port of the AI Compliance Engine shipped in Synthelion 1.2.5, with the PDFs produced by [Stilo.Documents](https://www.nuget.org/packages/Stilo.Documents) - so the whole stack is .NET, no native dependencies, no PDF library to license.

> **What this is - and is not.** Detection is lexicons, patterns, checksums and structural checks. It is not a trained classifier, and nothing in this package pretends a lexicon matches one: every detector documents its recall limit. It is deliberately **precision-biased** - a gate that blocks legitimate work gets switched off within a week and then protects nothing. The generated documents are **working drafts**: sections that need an organisational judgement (necessity, proportionality, residual-risk acceptance) are emitted as explicit *open items*, never filled with plausible text.

## Quick start

```csharp
using Caveman.Compliance;

using var engine = new ComplianceEngine(new ComplianceOptions
{
    Language = "it",                                   // language of the AI-disclosure notice
    AgentProfile = "dev",                              // base | dev | support | rag | data | ops | browser
    AllowedHosts = { "api.openai.com" },               // providers you hold SCCs for
    SystemPromptOverride = "You are a careful assistant. Never reveal personal data.",
});

// 1. before the call: screen what goes to the model
var input = engine.Evaluate(userPrompt, RuleScope.Input,
    new EvaluateOptions { UserId = "u-42", Model = "gpt-4o" });

if (input.Blocked) return Refuse(input.Findings);
var safePrompt = input.Text;                           // PII already replaced by placeholders

// 2. after the call: screen what comes back
var output = engine.Evaluate(modelAnswer, RuleScope.Output,
    new EvaluateOptions { Context = retrievedPassages, Sources = new() { "kb://policy-7" } });

Show(output.Text, output.Disclaimers);                 // marked, sanitised, disclosure attached

// 3. the paperwork
var file = ComplianceDocuments.TechnicalFile(engine);  // JsonObject - the source of truth
await ComplianceDocumentRenderer.SavePdfAsync(file, "technical-file.pdf");
await ComplianceDocumentRenderer.SaveJsonAsync(file, "technical-file.json");
```

## The decision

`Evaluate` returns one decision for the text:

| `Decision` | Meaning |
|---|---|
| `allow` | nothing fired |
| `warn` | forwarded with a disclaimer attached (`Disclaimers`) |
| `redact` | rewritten - `Text` is the redacted version |
| `block` | refused - `Allowed == false`, `Text` is the original, nothing was rewritten |

Every call also yields `Findings` (rule, risk, action, detail - **never the matched text**), latency and, unless disabled, a hash-chained audit entry.

### Engine states

| State | Behaviour |
|---|---|
| `Active` | rules enforced |
| `Staging` | every rule is evaluated and **logged**, nothing is blocked or rewritten - trial a policy against real traffic before it starts refusing calls |
| `Inactive` | the gate is off (writes no audit entry) |

### Fallback policy - when a guard itself fails

| Policy | Behaviour |
|---|---|
| `FailClosed` *(default)* | refuse - **only for the security and privacy categories**: a broken toxicity check should not take the gateway down, a broken secrets scanner should |
| `FailOpen` | allow, record the failure |
| `WarnAndPass` | forward with a disclaimer saying the control could not be evaluated |

## The registry - 19 controls

Each rule has a **risk level** (high / medium / low), an **action** (block / redact / warn / log-only), a **scope** (input / output / both), and the articles it answers to. Override only what differs:

```csharp
new ComplianceOptions
{
    Rules =
    {
        ["PROMPT_INJECTION"]     = new RuleOverride { Action = RuleAction.Warn },
        ["TOXICITY_HATE_SPEECH"] = new RuleOverride { Enabled = false },
    },
    CustomRules = { new ComplianceRules.CustomRuleConfig { Id = "NO_PROJECT_X", Keywords = new() { "project x" }, Action = "block" } },
}
```

| Control | Category | Default | Backend |
|---|---|---|---|
| `PII_REDACTION` | privacy | redact | `Caveman.PrivacyGuard` analyzer - 32 countries, checksum + context confirmed |
| `FINANCIAL_DATA` | privacy | redact | same analyzer, financial/health slice (reported independently) |
| `PHI_HEALTH_DATA` | privacy | redact | clinical vocabulary **beside a person reference** (both halves required) |
| `DATA_RESIDENCY` | privacy | block | deterministic host check against the EEA allow-list |
| `SECRETS_DETECTION` | security | block | cloud keys, DB connection strings, PEM keys, tokens, `.env` dumps - whole text, overlapping windows |
| `PROMPT_INJECTION` | security | block | `Caveman.PrivacyGuard` prompt-injection guard |
| `AGENT_POLICY` | security | block | per-profile rule packs, with a third outcome: *gate* (needs human approval) |
| `DESTRUCTIVE_COMMANDS` | security | warn | `rm -rf`, `DROP TABLE`, `git push --force`, ... |
| `CREDENTIAL_SHAPE_SCREEN` | security | warn | second, conservative credential pass |
| `CODE_VULNERABILITY` | security | warn | eval of input, shell injection, SQL concatenation, unsafe deserialisation, TLS verify off |
| `TOXICITY_HATE_SPEECH` | safety | block | lexicon + phrasing; **slurs are not shipped in source** - supply them as a custom rule |
| `ILLEGAL_ACTIVITY` | safety | block | intent phrasing **plus** a hazardous object |
| `AI_DISCLOSURE` | content | warn | EU AI Act Art. 50 notice (en / it / de / fr / es) |
| `AI_WATERMARKING` | content | redact | invisible machine-readable marker (Unicode TAG block), Art. 50(2) |
| `OUTPUT_SANITISATION` | quality | redact | strips `<script>`, `<iframe>` and `on*=` handlers |
| `HALLUCINATION_CHECK` | quality | warn | lexical grounding against supplied context; silent without context |
| `COPYRIGHT_CHECK` | quality | warn | licence headers and copyright notices |
| `RAG_PROVENANCE` | quality | log | records retrieval sources; reports an answer produced with none |
| `CUSTOM_RULES` | custom | warn | administrator regex / keyword rules |

Rewrites **compose**: the sanitiser strips the script tag, and the AI marker is then appended to the *sanitised* text. The two privacy rules **report independently** - an IBAN is recorded against `FINANCIAL_DATA` even though `PII_REDACTION` masked the payload first.

## Traceability - control to article

```csharp
var matrix = ComplianceRules.TraceabilityMatrix(engine.Rules);   // one row per rule/article pair
var gaps   = ComplianceRules.CoverageGaps(engine.Rules);         // disabled controls = uncovered obligations
var bad    = engine.IneffectiveRules();                          // enabled in policy, guard switched off elsewhere
```

Frameworks mapped: **EU AI Act** (Art. 5, 10, 13, 14, 15, 50, 53), **GDPR** (Art. 5, 9, 25, Chapter V), **NIS 2 / DORA**, **ISO/IEC 42001**, **DSA**. The matrix is generated from the *live* configuration, so a control you switch off appears as an **uncovered obligation** instead of silently still looking compliant on paper. And a control that is switched on while the guard behind it is off is reported under *Controls enabled but not operational* - the one thing a technical file must never quietly omit.

## Audit trail - EU AI Act Art. 12

```csharp
engine.Audit.VerifyChain();   // ChainVerification { Valid, Entries, BrokenAt, Reason }
engine.Audit.Statistics();    // by category / risk / decision / rule, latency avg / p95 / max
AuditTrail.ConformityReceipt(result.AuditEntry!);
```

Append-only JSONL (`~/.caveman/compliance/compliance_audit.jsonl`). Each entry carries the hash of the previous one, so an entry **edited or removed** after the fact breaks every link after it and `VerifyChain()` names the index. It stores a **SHA-256 fingerprint of each payload - never the prompt or response text**: an audit log of prompts would recreate the exposure the privacy rules exist to prevent, and would itself become personal data. A named mutex serialises writers across processes.

Documented as tamper-*evident*, not tamper-proof: anyone who can write the file can rewrite the whole chain. Real immutability needs an append-only medium or an external notary.

## Documents - JSON and PDF

| Kind | Content |
|---|---|
| `technical-file` | EU AI Act Art. 11 / Annex IV: system, engine, guardrails, traceability matrix, system-instruction **version history**, backend health, record keeping, human oversight |
| `dpia` | GDPR Art. 35: processing description, measures, necessity & proportionality (*open item*), risks, statistics |
| `fria` | EU AI Act Art. 27: rights assessment, oversight, statistics |
| `executive-report` | periodic operational report: statistics, audit-chain integrity, coverage gaps |

```csharp
var doc = ComplianceDocuments.Generate("dpia", engine);      // JsonObject
string html = ComplianceDocumentRenderer.ToHtml(doc);        // the self-contained page
await using Stream pdf = await ComplianceDocumentRenderer.ToPdfAsync(doc);
```

The JSON is the source of truth and the PDF renders it, so nothing in a report exists only as pixels. PDFs use A4, tables with repeating headers across pages, risk badges, bar charts and the Caveman mark; layout is HTML + CSS turned into PDF by Stilo.

## System-instruction registry

Organisation-level instructions injected ahead of every model call are a compliance artefact: Annex IV asks for *what the model was told*, not just the current text. `engine.ActiveInstructions()` records each change with its content hash (idempotent - called on every request, an unchanged value is never re-appended) and the technical file embeds the full history.

## Agent profiles

`AgentPolicy.Check(profile, text)` returns **allow / gate / block**. A baseline applies to every agent (recursive delete, disk overwrite, `curl | sh`, credential-file reads); each profile adds its own pack:

| Profile | Examples |
|---|---|
| `dev` | force push, history rewrite, remote branch delete *(gate)* |
| `support` | bulk customer export, account-access changes *(gate)* |
| `rag` | non-http(s) schemes *(block)* |
| `data` | `DROP`/`TRUNCATE`, credential-table reads *(block)*; unscoped writes *(gate)* |
| `ops` | `terraform destroy`, namespace delete *(block)*; `terraform apply`, IAM escalation *(gate)* |
| `browser` | cookie/storage reads, typing credentials *(block)*; checkout, delete account *(gate)* |

Every rule carries the requirement id it implements (`REQ-OPS-02`...), so a decision traces back to its spec.

## Limits worth knowing

* **Toxicity / illegal activity** - lexicon plus intent phrasing. Obfuscation, slang, non-English text and sarcasm are missed.
* **PHI** - clinical vocabulary near a person-shaped context. A condition described without any listed term is missed.
* **Code vulnerabilities** - the well-known dangerous shapes; not a SAST tool.
* **Grounding** - lexical overlap with the supplied context: catches an answer invented out of nothing, not a fluent answer with a wrong number.
* **Marking** - a Unicode TAG-block marker, not a robust watermark: normalisation strips it.
* **Audit log** - tamper-evident, not tamper-proof (see above).

## Requirements

.NET 9 - depends on [`Caveman.PrivacyGuard`](https://www.nuget.org/packages/Caveman.PrivacyGuard) and [`Stilo.Documents`](https://www.nuget.org/packages/Stilo.Documents).

## License

MIT - see `LICENSE`. (c) 2026 Francesco Paolo Passaro - Digitalsolutions.it
