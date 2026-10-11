// ------------------------------------------------------------------------------
// Caveman.Compliance
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
//
// Compliance rule registry and regulatory traceability matrix. Port of Synthelion's
// compliance/rules.py: the rules are bindings, not new detection logic - each one names
// the guard that implements it and wraps it in the vocabulary a compliance officer uses
// (risk level, remediation action, scope, and the articles of law the control answers).
// ------------------------------------------------------------------------------
using System.Text.RegularExpressions;

namespace Caveman.Compliance;

/// <summary>Functional area of a control.</summary>
public enum RuleCategory { Privacy, Security, Safety, Content, Quality, Custom }

/// <summary>Risk attached to a control.</summary>
public enum RiskLevel { High, Medium, Low }

/// <summary>What the engine does when a rule fires.</summary>
public enum RuleAction
{
    /// <summary>Refuse the call outright.</summary>
    Block,
    /// <summary>Rewrite the text, then continue.</summary>
    Redact,
    /// <summary>Attach a disclaimer, then continue.</summary>
    Warn,
    /// <summary>Allow, record in the audit trail.</summary>
    LogOnly,
}

/// <summary>Whether a rule inspects what goes to the model, what comes back, or both.</summary>
public enum RuleScope { Input, Output, Both }

public static class EnumText
{
    public static string Wire(this RuleCategory c) => c.ToString().ToLowerInvariant();
    public static string Wire(this RiskLevel r) => r.ToString().ToLowerInvariant();
    public static string Wire(this RuleScope s) => s.ToString().ToLowerInvariant();
    public static string Wire(this RuleAction a) => a switch
    {
        RuleAction.LogOnly => "log_only",
        _ => a.ToString().ToLowerInvariant(),
    };

    public static bool Covers(this RuleScope rule, RuleScope requested) => rule == RuleScope.Both || rule == requested;

    public static bool TryParse(string? s, out RuleCategory v) => Enum.TryParse(s, true, out v);
    public static bool TryParse(string? s, out RiskLevel v) => Enum.TryParse(s, true, out v);
    public static bool TryParse(string? s, out RuleScope v) => Enum.TryParse(s, true, out v);
    public static bool TryParse(string? s, out RuleAction v) =>
        Enum.TryParse((s ?? "").Replace("_", ""), true, out v);
}

/// <summary>One article of law a control exists to satisfy.</summary>
public sealed record LegalReference(string Framework, string Article, string Obligation);

/// <summary>
/// One control. <see cref="Backend"/> names the guard implementing the detection - the engine
/// dispatches on it, so a rule is configuration, not code.
/// </summary>
public sealed class ComplianceRule
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public RuleCategory Category { get; set; } = RuleCategory.Custom;
    public string Backend { get; set; } = "";
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Medium;
    public RuleAction Action { get; set; } = RuleAction.LogOnly;
    public RuleScope Scope { get; set; } = RuleScope.Both;
    public bool Enabled { get; set; } = true;
    public string Description { get; set; } = "";
    public IReadOnlyList<LegalReference> Legal { get; set; } = Array.Empty<LegalReference>();

    /// <summary>Regular expression of an administrator-defined rule (backend <c>custom_regex</c>).</summary>
    public string? Pattern { get; set; }

    public ComplianceRule Clone() => (ComplianceRule)MemberwiseClone();
}

/// <summary>A row of the traceability matrix: control to article.</summary>
public sealed record TraceabilityRow(
    string RuleId, string Module, string Category, string Framework, string Article,
    string Obligation, bool Enabled, string RiskLevel, string Action);

public static class ComplianceRules
{
    private const string AiAct = "EU AI Act (Reg. 2024/1689)";
    private const string Gdpr = "GDPR (Reg. 2016/679)";
    private const string Nis2 = "NIS 2 / DORA";
    private const string Iso = "ISO/IEC 42001";

    private static LegalReference L(string fw, string art, string obl) => new(fw, art, obl);

    /// <summary>Fresh copies of the built-in registry, so a caller mutating a rule cannot corrupt it.</summary>
    public static List<ComplianceRule> Default() => Build().Select(r => r.Clone()).ToList();

    private static IEnumerable<ComplianceRule> Build()
    {
        // ── Privacy ───────────────────────────────────────────────────────
        yield return new ComplianceRule
        {
            Id = "PII_REDACTION", Title = "PII detection and redaction", Category = RuleCategory.Privacy,
            Backend = "privacy_analyzer", RiskLevel = RiskLevel.High, Action = RuleAction.Redact, Scope = RuleScope.Both,
            Description = "Names, national IDs, phone numbers, addresses and email are masked with recoverable placeholders before the text reaches a third-party model.",
            Legal = new[]
            {
                L(Gdpr, "Art. 5(1)(c)", "Data minimisation - only data necessary for the purpose may be processed."),
                L(Gdpr, "Art. 25", "Privacy by design and by default."),
                L(AiAct, "Art. 10", "Data governance for high-risk systems."),
            },
        };
        yield return new ComplianceRule
        {
            Id = "FINANCIAL_DATA", Title = "Financial and health data protection", Category = RuleCategory.Privacy,
            Backend = "privacy_analyzer", RiskLevel = RiskLevel.High, Action = RuleAction.Redact, Scope = RuleScope.Both,
            Description = "Payment card numbers (PCI-DSS), IBANs and health identifiers are detected and masked. Backed by the same analyzer as PII_REDACTION, scoped to its financial and health categories.",
            Legal = new[]
            {
                L(Gdpr, "Art. 9", "Special categories of personal data."),
                L(Nis2, "PCI-DSS", "Protection of cardholder data."),
            },
        };

        // ── Security ──────────────────────────────────────────────────────
        yield return new ComplianceRule
        {
            Id = "SECRETS_DETECTION", Title = "Secrets and API key detection", Category = RuleCategory.Security,
            Backend = "enterprise_guard", RiskLevel = RiskLevel.High, Action = RuleAction.Block, Scope = RuleScope.Both,
            Description = "Cloud credentials, database connection strings, private keys and API tokens. Always blocks rather than redacts - a live secret has no safe redacted form.",
            Legal = new[]
            {
                L(Nis2, "Art. 21", "Technical measures to manage cybersecurity risk."),
                L(Iso, "A.8", "Protection of authentication information."),
            },
        };
        yield return new ComplianceRule
        {
            Id = "PROMPT_INJECTION", Title = "Prompt injection and jailbreak defence", Category = RuleCategory.Security,
            Backend = "prompt_injection_guard", RiskLevel = RiskLevel.High, Action = RuleAction.Block, Scope = RuleScope.Input,
            Description = "Heuristic detection of attempts to override system instructions, exfiltrate the system prompt, or coerce the model out of its configured behaviour.",
            Legal = new[] { L(AiAct, "Art. 15", "Accuracy, robustness and cybersecurity.") },
        };
        yield return new ComplianceRule
        {
            Id = "AGENT_POLICY", Title = "Per-agent-type guardrails", Category = RuleCategory.Security,
            Backend = "agent_policy", RiskLevel = RiskLevel.High, Action = RuleAction.Block, Scope = RuleScope.Input,
            Description = "Destructive commands and gated operations requiring human approval, per agent profile (base, dev, support, rag, data, ops, browser).",
            Legal = new[]
            {
                L(AiAct, "Art. 15", "Robustness against adversarial use."),
                L(AiAct, "Art. 14", "Human oversight - gated actions require an operator."),
            },
        };
        yield return new ComplianceRule
        {
            Id = "DESTRUCTIVE_COMMANDS", Title = "Destructive command detection", Category = RuleCategory.Security,
            Backend = "safety_guard", RiskLevel = RiskLevel.Medium, Action = RuleAction.Warn, Scope = RuleScope.Output,
            Description = "Flags destructive shell commands present in generated output before a human or an agent can act on them.",
            Legal = new[] { L(AiAct, "Art. 15", "Robustness - preventing harmful automated action.") },
        };
        yield return new ComplianceRule
        {
            Id = "CREDENTIAL_SHAPE_SCREEN", Title = "Credential-shape secondary screen", Category = RuleCategory.Security,
            Backend = "sensitive_guard", RiskLevel = RiskLevel.Medium, Action = RuleAction.Warn, Scope = RuleScope.Both,
            Description = "A second, deliberately conservative pass for credential-shaped strings on the persistence path. Narrower than SECRETS_DETECTION and not a content-safety control: it does not screen for toxicity, hate speech or illegal-activity requests.",
            Legal = new[] { L(Nis2, "Art. 21", "Technical measures to manage cybersecurity risk.") },
        };

        // ── Transparency ──────────────────────────────────────────────────
        yield return new ComplianceRule
        {
            Id = "AI_DISCLOSURE", Title = "AI interaction disclosure", Category = RuleCategory.Content,
            Backend = "ai_transparency_notice", RiskLevel = RiskLevel.Medium, Action = RuleAction.Warn, Scope = RuleScope.Output,
            Description = "Attaches the notice informing the person that they are interacting with an automated system, in their configured language.",
            Legal = new[] { L(AiAct, "Art. 50", "Transparency obligations for certain AI systems.") },
        };

        // ── Quality ───────────────────────────────────────────────────────
        yield return new ComplianceRule
        {
            Id = "OUTPUT_SANITISATION", Title = "Output sanitisation", Category = RuleCategory.Quality,
            Backend = "output_sanitiser", RiskLevel = RiskLevel.Low, Action = RuleAction.Redact, Scope = RuleScope.Output,
            Description = "Strips script tags and event-handler attributes from generated output before it reaches a client that may render it.",
            Legal = new[] { L(AiAct, "Art. 15", "Robustness of system output.") },
        };

        // ── Controls backed by the detectors in this package ──────────────
        yield return new ComplianceRule
        {
            Id = "TOXICITY_HATE_SPEECH", Title = "Toxicity and hate-speech filter", Category = RuleCategory.Safety,
            Backend = "toxicity", RiskLevel = RiskLevel.High, Action = RuleAction.Block, Scope = RuleScope.Both,
            Description = "Abusive language, harassment and targeting of protected groups. Lexicon and phrasing based, not a trained classifier: obfuscation, slang and non-English text are missed. Precision-biased on purpose.",
            Legal = new[]
            {
                L(AiAct, "Art. 5", "Prohibited practices."),
                L("DSA (Reg. 2022/2065)", "Art. 34", "Systemic-risk mitigation for harmful content."),
            },
        };
        yield return new ComplianceRule
        {
            Id = "ILLEGAL_ACTIVITY", Title = "Hazardous and illegal-activity screening", Category = RuleCategory.Safety,
            Backend = "illegal_activity", RiskLevel = RiskLevel.High, Action = RuleAction.Block, Scope = RuleScope.Both,
            Description = "Requests for weapons, controlled substances or self-harm instructions. Requires intent phrasing beside a hazardous object, so a news report or a chemistry lesson does not fire it.",
            Legal = new[] { L(AiAct, "Art. 5", "Prohibited practices.") },
        };
        yield return new ComplianceRule
        {
            Id = "PHI_HEALTH_DATA", Title = "Health data (PHI) detection", Category = RuleCategory.Privacy,
            Backend = "phi", RiskLevel = RiskLevel.High, Action = RuleAction.Redact, Scope = RuleScope.Both,
            Description = "Clinical vocabulary tied to an identifiable person. A medical article is not PHI and a bare name is ordinary PII, so both halves are required.",
            Legal = new[] { L(Gdpr, "Art. 9", "Special categories - data concerning health.") },
        };
        yield return new ComplianceRule
        {
            Id = "DATA_RESIDENCY", Title = "Cross-border transfer and data residency control", Category = RuleCategory.Privacy,
            Backend = "data_residency", RiskLevel = RiskLevel.High, Action = RuleAction.Block, Scope = RuleScope.Input,
            Description = "Flags endpoints outside the EEA allow-list. Deterministic host check; an unknown host counts as a third-country transfer, since both carry the same obligation. Providers covered by standard contractual clauses go in the allowed hosts.",
            Legal = new[] { L(Gdpr, "Chapter V", "Transfers of personal data to third countries.") },
        };
        yield return new ComplianceRule
        {
            Id = "CODE_VULNERABILITY", Title = "Code security and vulnerability scanning", Category = RuleCategory.Security,
            Backend = "code_vulnerability", RiskLevel = RiskLevel.Medium, Action = RuleAction.Warn, Scope = RuleScope.Both,
            Description = "Well-known dangerous code shapes - eval of input, shell injection, SQL concatenation, unsafe deserialisation, disabled TLS verification. Pattern based, like a linter's security rules; not a SAST tool.",
            Legal = new[] { L(AiAct, "Art. 15", "Accuracy, robustness and cybersecurity.") },
        };
        yield return new ComplianceRule
        {
            Id = "HALLUCINATION_CHECK", Title = "Factuality and hallucination detection", Category = RuleCategory.Quality,
            Backend = "grounding", RiskLevel = RiskLevel.Medium, Action = RuleAction.Warn, Scope = RuleScope.Output,
            Description = "Lexical grounding of the answer against the supplied context. Catches an answer invented out of nothing; will not catch a fluent answer with a wrong number. Silent when no context is supplied.",
            Legal = new[] { L(AiAct, "Art. 15", "Accuracy of the AI system.") },
        };
        yield return new ComplianceRule
        {
            Id = "COPYRIGHT_CHECK", Title = "Copyright and licence screening", Category = RuleCategory.Quality,
            Backend = "copyright", RiskLevel = RiskLevel.Medium, Action = RuleAction.Warn, Scope = RuleScope.Output,
            Description = "Licence headers and copyright notices in generated output. Detects a declared licence; it cannot tell that an unmarked passage was copied from a protected work, which would need a corpus to compare against.",
            Legal = new[] { L(AiAct, "Art. 53", "GPAI obligations - Union copyright law.") },
        };
        yield return new ComplianceRule
        {
            Id = "AI_WATERMARKING", Title = "Machine-readable marking of generated content", Category = RuleCategory.Content,
            Backend = "content_marker", RiskLevel = RiskLevel.Medium, Action = RuleAction.Redact, Scope = RuleScope.Output,
            Description = "Marks generated content with an invisible, machine-readable tag (AI Act Art. 50(2)) and flags output that carries none. A marking, not a robust watermark: Unicode normalisation strips it.",
            Legal = new[] { L(AiAct, "Art. 50(2)", "Marking of AI-generated content in a machine-readable format.") },
        };
        yield return new ComplianceRule
        {
            Id = "RAG_PROVENANCE", Title = "Data provenance and RAG source citation", Category = RuleCategory.Quality,
            Backend = "rag_provenance", RiskLevel = RiskLevel.Low, Action = RuleAction.LogOnly, Scope = RuleScope.Output,
            Description = "Records the retrieved sources behind an answer in the audit trail. The caller supplies them; the rule reports when an answer was produced with none, which is the case an auditor needs to see.",
            Legal = new[] { L(AiAct, "Art. 13", "Transparency and provision of information to deployers.") },
        };
        yield return new ComplianceRule
        {
            Id = "CUSTOM_RULES", Title = "Administrator-defined regex and keyword rules", Category = RuleCategory.Custom,
            Backend = "custom_registry", RiskLevel = RiskLevel.Low, Action = RuleAction.Warn, Scope = RuleScope.Both,
            Description = "Administrator-defined regex and keyword rules, merged into this registry at load time. This entry is the capability marker; each configured rule appears in the registry in its own right.",
            Legal = Array.Empty<LegalReference>(),
        };
    }

    /// <summary>One administrator-defined rule, as read from configuration.</summary>
    public sealed class CustomRuleConfig
    {
        public string Id { get; set; } = "";
        public string? Title { get; set; }
        public string? Pattern { get; set; }
        public List<string>? Keywords { get; set; }
        public string? Category { get; set; }
        public string? RiskLevel { get; set; }
        public string? Action { get; set; }
        public string? Scope { get; set; }
        public bool Enabled { get; set; } = true;
        public string? Description { get; set; }
        public List<LegalReference>? Legal { get; set; }
    }

    /// <summary>
    /// Builds administrator-defined rules. Each needs an id and either a <c>Pattern</c> or <c>Keywords</c>
    /// (matched whole-word, case-insensitively). Missing fields fall back to a conservative default - warn,
    /// medium risk, both scopes - so a half-filled entry cannot silently become a blocker. An invalid regex
    /// is skipped rather than thrown: one malformed entry must not take the engine down.
    /// </summary>
    public static List<ComplianceRule> FromConfig(IEnumerable<CustomRuleConfig>? entries)
    {
        var result = new List<ComplianceRule>();
        foreach (var e in entries ?? Array.Empty<CustomRuleConfig>())
        {
            if (string.IsNullOrWhiteSpace(e.Id)) continue;
            var pattern = e.Pattern;
            if (string.IsNullOrEmpty(pattern) && e.Keywords is { Count: > 0 })
                pattern = @"\b(" + string.Join("|", e.Keywords.Select(Regex.Escape)) + @")\b";
            if (string.IsNullOrEmpty(pattern)) continue;
            try { _ = new Regex(pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)); }
            catch (ArgumentException) { continue; }

            var rule = new ComplianceRule
            {
                Id = e.Id, Title = e.Title ?? e.Id, Backend = "custom_regex", Pattern = pattern, Enabled = e.Enabled,
                Description = e.Description ?? "Administrator-defined rule.",
                Action = RuleAction.Warn, RiskLevel = RiskLevel.Medium, Scope = RuleScope.Both, Category = RuleCategory.Custom,
                Legal = (e.Legal ?? new()).ToArray(),
            };
            if (e.Category is not null) { if (!EnumText.TryParse(e.Category, out RuleCategory c)) continue; rule.Category = c; }
            if (e.RiskLevel is not null) { if (!EnumText.TryParse(e.RiskLevel, out RiskLevel r)) continue; rule.RiskLevel = r; }
            if (e.Action is not null) { if (!EnumText.TryParse(e.Action, out RuleAction a)) continue; rule.Action = a; }
            if (e.Scope is not null) { if (!EnumText.TryParse(e.Scope, out RuleScope s)) continue; rule.Scope = s; }
            result.Add(rule);
        }
        return result;
    }

    /// <summary>
    /// Functionality to legal obligation, one row per rule/article pair, generated from the live
    /// configuration - so a disabled control shows up as an uncovered obligation instead of silently
    /// continuing to look compliant on paper.
    /// </summary>
    public static List<TraceabilityRow> TraceabilityMatrix(IEnumerable<ComplianceRule>? rules = null)
    {
        var rows = new List<TraceabilityRow>();
        foreach (var rule in rules ?? Default())
            foreach (var l in rule.Legal)
                rows.Add(new TraceabilityRow(rule.Id, rule.Title, rule.Category.Wire(), l.Framework, l.Article,
                    l.Obligation, rule.Enabled, rule.RiskLevel.Wire(), rule.Action.Wire()));
        return rows;
    }

    /// <summary>Obligations left uncovered because their rule is disabled.</summary>
    public static List<TraceabilityRow> CoverageGaps(IEnumerable<ComplianceRule>? rules = null) =>
        TraceabilityMatrix(rules).Where(r => !r.Enabled).ToList();
}
