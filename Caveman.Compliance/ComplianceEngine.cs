// ------------------------------------------------------------------------------
// Caveman.Compliance
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
//
// The compliance engine - one gate in front of every guard Caveman has. Port of Synthelion's
// compliance/engine.py. It runs almost no detection of its own: it takes the guards that already
// exist (Caveman.PrivacyGuard's PrivacyAnalyzer and PromptInjectionGuard, plus the secrets,
// destructive-command and agent-policy guards in this package), applies them in the order and with
// the semantics a compliance policy describes (risk level, remediation action, input/output scope),
// and produces a single decision plus an audit record.
//
// Engine states:
//   Active   - rules are enforced
//   Staging  - every rule is evaluated and logged, but nothing is ever blocked or rewritten, so a
//              policy can be trialled against real traffic before it starts refusing calls
//   Inactive - the gate is off
//
// The fallback policy decides what happens when a guard itself fails. FailClosed refuses the call
// (for the security and privacy categories only - a broken toxicity check should not take the gateway
// down, a broken secrets scanner should); FailOpen allows it and records the failure; WarnAndPass
// forwards the call with a disclaimer saying the control could not be evaluated.
// ------------------------------------------------------------------------------
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Text.Json.Nodes;
using Caveman.PrivacyGuard;

namespace Caveman.Compliance;

public enum EngineStatus { Active, Staging, Inactive }

public enum FallbackPolicy { FailClosed, FailOpen, WarnAndPass }

/// <summary>Per-rule override applied on top of the defaults, so a deployment only states what it changes.</summary>
public sealed class RuleOverride
{
    public bool? Enabled { get; set; }
    public RiskLevel? RiskLevel { get; set; }
    public RuleAction? Action { get; set; }
    public RuleScope? Scope { get; set; }
}

/// <summary>Engine configuration.</summary>
public sealed class ComplianceOptions
{
    public EngineStatus Status { get; set; } = EngineStatus.Active;
    public FallbackPolicy Fallback { get; set; } = FallbackPolicy.FailClosed;
    /// <summary>Language of the AI transparency notice and of the PrivacyGuard messages (en, it, de, fr, es).</summary>
    public string Language { get; set; } = "en";
    /// <summary>Organisation-level system instructions injected ahead of every model call by the host.</summary>
    public string SystemPromptOverride { get; set; } = "";
    /// <summary>Agent profile for the AGENT_POLICY rule: base, dev, support, rag, data, ops, browser.</summary>
    public string AgentProfile { get; set; } = "base";
    /// <summary>Hosts accepted by the DATA_RESIDENCY rule regardless of suffix (providers covered by SCCs).</summary>
    public List<string> AllowedHosts { get; set; } = new();
    public Dictionary<string, RuleOverride> Rules { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<ComplianceRules.CustomRuleConfig> CustomRules { get; set; } = new();
    /// <summary>Folder of the audit trail and instruction registry; defaults to <c>~/.caveman/compliance</c>.</summary>
    public string? AuditDirectory { get; set; }
    /// <summary>Backends switched off elsewhere; a rule enabled in policy whose backend is off is reported as ineffective.</summary>
    public HashSet<string> DisabledBackends { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>One rule that fired (or failed) during an evaluation.</summary>
public sealed record Finding(
    string RuleId, string Title, string Category, string RiskLevel, string Action,
    string Detail = "", IReadOnlyList<string>? MatchedCategories = null, string BackendError = "")
{
    public JsonObject ToJson()
    {
        var cats = new JsonArray();
        foreach (var c in MatchedCategories ?? Array.Empty<string>()) cats.Add(c);
        return new JsonObject
        {
            ["rule_id"] = RuleId, ["title"] = Title, ["category"] = Category, ["risk_level"] = RiskLevel,
            ["action"] = Action, ["detail"] = Detail, ["matched_categories"] = cats, ["backend_error"] = BackendError,
        };
    }
}

/// <summary>Per-call context for <see cref="ComplianceEngine.Evaluate"/>.</summary>
public sealed class EvaluateOptions
{
    public string UserId { get; set; } = "";
    public string Model { get; set; } = "";
    public string ClientIp { get; set; } = "";
    public string RequestId { get; set; } = "";
    /// <summary>Retrieved material the answer should be grounded in (RAG); the grounding rule is silent without it.</summary>
    public string Context { get; set; } = "";
    /// <summary>Identifiers of the retrieval sources behind the answer (AI Act Art. 13).</summary>
    public List<string> Sources { get; set; } = new();
    public bool WriteAudit { get; set; } = true;
}

/// <summary>The decision for one piece of text.</summary>
public sealed class ComplianceResult
{
    public bool Allowed { get; init; }
    public bool Blocked => !Allowed;
    /// <summary>The text as it leaves the gate: redacted when a rule rewrote it; the original when blocked.</summary>
    public string Text { get; init; } = "";
    /// <summary><c>allow</c>, <c>redact</c>, <c>warn</c> or <c>block</c>.</summary>
    public string Decision { get; init; } = "allow";
    public IReadOnlyList<Finding> Findings { get; init; } = Array.Empty<Finding>();
    public IReadOnlyList<string> Disclaimers { get; init; } = Array.Empty<string>();
    public double LatencyMs { get; init; }
    public string EngineStatus { get; init; } = "active";
    public JsonObject? AuditEntry { get; init; }

    public JsonObject ToJson()
    {
        var f = new JsonArray(); foreach (var x in Findings) f.Add(x.ToJson());
        var d = new JsonArray(); foreach (var x in Disclaimers) d.Add(x);
        return new JsonObject
        {
            ["allowed"] = Allowed, ["decision"] = Decision, ["text"] = Text, ["findings"] = f, ["disclaimers"] = d,
            ["latency_ms"] = Math.Round(LatencyMs, 3), ["engine_status"] = EngineStatus, ["audit"] = AuditEntry?.DeepClone(),
        };
    }
}

/// <summary>Per-rule operational state: is the guard behind an enabled rule actually running?</summary>
public sealed record BackendHealth(string RuleId, string Title, string Backend, bool RuleEnabled, string BackendState, bool Effective, string Note)
{
    public JsonObject ToJson() => new()
    {
        ["rule_id"] = RuleId, ["title"] = Title, ["backend"] = Backend, ["rule_enabled"] = RuleEnabled,
        ["backend_state"] = BackendState, ["effective"] = Effective, ["note"] = Note,
    };
}

/// <summary>Evaluates text against the configured rule set.</summary>
public sealed class ComplianceEngine : IDisposable
{
    private static readonly HashSet<string> DetectorBackends = new(StringComparer.OrdinalIgnoreCase)
    {
        "toxicity", "illegal_activity", "phi", "data_residency", "code_vulnerability", "copyright",
        "grounding", "content_marker", "rag_provenance", "custom_registry",
    };

    private static readonly HashSet<string> BuiltInBackends = new(StringComparer.OrdinalIgnoreCase)
    {
        "privacy_analyzer", "enterprise_guard", "prompt_injection_guard", "agent_policy", "safety_guard",
        "sensitive_guard", "ai_transparency_notice", "output_sanitiser", "custom_regex",
    };

    // A backend failure in these categories is a security event, not a hiccup: if the secrets scanner is
    // down we cannot claim the payload is clean.
    private static readonly HashSet<RuleCategory> FailClosedCategories = new() { RuleCategory.Security, RuleCategory.Privacy };

    // Every backend that can return a replacement must see the accumulated text, or its rewrite silently
    // discards the previous rule's. privacy_analyzer is deliberately absent: it detects against the original
    // so the two privacy rules stay independent.
    private static readonly HashSet<string> Transforming = new(StringComparer.OrdinalIgnoreCase) { "output_sanitiser", "content_marker", "phi" };

    // PrivacyAnalyzer reports one flat category list, but the two privacy rules answer to different
    // articles. Split its output so each rule fires only for its own slice.
    private static readonly HashSet<string> FinancialCategories = new(StringComparer.OrdinalIgnoreCase)
    {
        "Credit Card", "IBAN", "Bank Account", "SWIFT/BIC", "Health", "Medical",
    };

    private readonly PrivacyAnalyzer _privacy;
    private readonly PromptInjectionGuard _injection = new();
    private readonly object _privacyLock = new();

    public List<ComplianceRule> Rules { get; }
    public ComplianceOptions Options { get; }
    public AuditTrail Audit { get; }
    public SystemInstructionRegistry Instructions { get; }

    public EngineStatus Status { get => Options.Status; set => Options.Status = value; }
    public FallbackPolicy Fallback => Options.Fallback;
    public string Language => Options.Language;
    public string AgentProfile => Options.AgentProfile;
    public string SystemPromptOverride => Options.SystemPromptOverride;

    public static string Wire(EngineStatus s) => s.ToString().ToLowerInvariant();
    public static string Wire(FallbackPolicy f) => f switch
    {
        FallbackPolicy.FailClosed => "fail_closed",
        FallbackPolicy.FailOpen => "fail_open",
        _ => "warn_and_pass",
    };

    public ComplianceEngine(ComplianceOptions? options = null, IEnumerable<ComplianceRule>? rules = null)
    {
        Options = options ?? new ComplianceOptions();
        Rules = BuildRules(Options, rules);
        Audit = new AuditTrail(Options.AuditDirectory);
        Instructions = new SystemInstructionRegistry(Options.AuditDirectory);
        _privacy = new PrivacyAnalyzer { EnableAutoMasking = true };
    }

    private static List<ComplianceRule> BuildRules(ComplianceOptions o, IEnumerable<ComplianceRule>? supplied)
    {
        var rules = supplied?.Select(r => r.Clone()).ToList() ?? ComplianceRules.Default();

        // Per-rule overrides on top of the defaults.
        foreach (var rule in rules)
        {
            if (!o.Rules.TryGetValue(rule.Id, out var ov)) continue;
            if (ov.Enabled is { } en) rule.Enabled = en;
            if (ov.RiskLevel is { } rl) rule.RiskLevel = rl;
            if (ov.Action is { } ac) rule.Action = ac;
            if (ov.Scope is { } sc) rule.Scope = sc;
        }

        // Admin-defined rules extend the registry; a custom id that collides with a built-in one replaces it,
        // so an operator can re-scope a shipped rule without editing code.
        var byId = new Dictionary<string, ComplianceRule>(StringComparer.Ordinal);
        foreach (var r in rules) byId[r.Id] = r;
        foreach (var c in ComplianceRules.FromConfig(o.CustomRules)) byId[c.Id] = c;
        return byId.Values.ToList();
    }

    public ComplianceRule? Rule(string id) => Rules.FirstOrDefault(r => r.Id == id);

    public IEnumerable<ComplianceRule> ActiveRules(RuleScope scope) => Rules.Where(r => r.Enabled && r.Scope.Covers(scope));

    // ── backends ────────────────────────────────────────────────────────

    private sealed class EvalContext
    {
        public string Context = "";
        public IReadOnlyList<string> Sources = Array.Empty<string>();
        public PrivacyAnalysisResult? PrivacyCache;
        public string? PrivacyCacheText;
    }

    private Detection RunBackend(ComplianceRule rule, string text, EvalContext ctx)
    {
        switch (rule.Backend)
        {
            case "privacy_analyzer": return BackendPrivacy(rule, text, ctx);
            case "enterprise_guard":
            {
                var found = SecretScanner.Find(text);
                return found is null ? Detection.None : Detection.Hit(found.Value.Name, found.Value.Category);
            }
            case "prompt_injection_guard":
            {
                var r = _injection.Analyze(text);
                return r.IsClean ? Detection.None : Detection.Hit($"score {r.Score}, risk {r.RiskLevel}", r.DetectedCategories.ToArray());
            }
            case "agent_policy":
            {
                var d = AgentPolicy.Check(Options.AgentProfile, text);
                return d.Allowed ? Detection.None
                    : Detection.Hit($"{d.Verdict.ToString().ToLowerInvariant()}: {d.Reason}", d.Requirement ?? "policy");
            }
            case "safety_guard":
            {
                var found = DestructiveCommands.Find(text);
                return found is null ? Detection.None : Detection.Hit($"destructive command: {found}", "destructive_command");
            }
            case "sensitive_guard":
            {
                var found = SecretScanner.Find(text);
                return found is null ? Detection.None : Detection.Hit($"sensitive content: {found.Value.Name}", "sensitive");
            }
            // Always "fires": the disclosure is an obligation to attach a notice, not a detection.
            case "ai_transparency_notice": return Detection.Hit("AI interaction disclosure attached", "transparency");
            case "output_sanitiser": return ComplianceDetectors.SanitiseOutput(text);
            case "custom_regex": return BackendCustom(rule, text);
            case "toxicity": return ComplianceDetectors.Toxicity(text);
            case "illegal_activity": return ComplianceDetectors.IllegalActivity(text);
            case "phi": return ComplianceDetectors.Phi(text);
            case "data_residency": return ComplianceDetectors.DataResidency(text, Options.AllowedHosts);
            case "code_vulnerability": return ComplianceDetectors.CodeVulnerabilities(text);
            case "copyright": return ComplianceDetectors.Copyright(text);
            case "grounding": return ComplianceDetectors.Ungrounded(text, ctx.Context);
            case "rag_provenance":
                // Fires when an answer was produced with no recorded sources - that absence is the finding.
                return ctx.Sources.Count > 0 ? Detection.None
                    : Detection.Hit("no retrieval sources recorded for this answer", "no_provenance");
            case "custom_registry": return Detection.None; // capability marker, each custom rule is its own entry
            case "content_marker":
            {
                var d = ComplianceDetectors.MissingMarker(text);
                // The remediation IS the marking: attach it rather than only reporting it is absent.
                return d.Fired ? d with { Replacement = ComplianceDetectors.EmbedContentMarker(text) } : d;
            }
            default:
                throw new NotImplementedException($"no backend implementing '{rule.Backend}'");
        }
    }

    /// <summary>
    /// One analysis per evaluation, shared by every privacy rule. Letting each re-scan the current text would
    /// mean whichever runs first redacts the payload and the second then finds nothing - so a real IBAN would
    /// be masked but never recorded against the control that answers for it.
    /// </summary>
    private PrivacyAnalysisResult PrivacyAnalysis(string text, EvalContext ctx)
    {
        if (ctx.PrivacyCache is not null && ctx.PrivacyCacheText == text) return ctx.PrivacyCache;
        PrivacyAnalysisResult result;
        lock (_privacyLock) result = _privacy.Analyze(text, Options.Language, null);
        ctx.PrivacyCache = result; ctx.PrivacyCacheText = text;
        return result;
    }

    private Detection BackendPrivacy(ComplianceRule rule, string text, EvalContext ctx)
    {
        var result = PrivacyAnalysis(text, ctx);
        if (result.DetectedCategories.Count == 0) return Detection.None;
        var financial = rule.Id == "FINANCIAL_DATA";
        var mine = result.DetectedCategories.Where(c => FinancialCategories.Contains(c) == financial).ToArray();
        if (mine.Length == 0) return Detection.None;
        // Masking is all-or-nothing in the analyzer, so whichever privacy rule runs first redacts everything it
        // found; the other still reports its own categories for the audit trail.
        var replacement = rule.Action == RuleAction.Redact && !string.IsNullOrEmpty(result.MaskedText) ? result.MaskedText : null;
        return new Detection(true, $"{mine.Length} category/ies matched, overall risk {result.RiskLevel}", mine, replacement);
    }

    private static Detection BackendCustom(ComplianceRule rule, string text)
    {
        if (string.IsNullOrEmpty(rule.Pattern)) return Detection.None;
        var m = Regex.Match(text, rule.Pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));
        // Report THAT it matched and how long the match was - never the matched text, which is exactly the
        // content the rule exists to keep out of logs.
        return m.Success ? Detection.Hit($"custom rule matched ({m.Length} chars)", rule.Id) : Detection.None;
    }

    // ── backend health ──────────────────────────────────────────────────

    private (string State, string Note) BackendState(string backend)
    {
        if (Options.DisabledBackends.Contains(backend))
            return ("disabled", $"backend '{backend}' is switched off in the configuration");
        if (BuiltInBackends.Contains(backend) || DetectorBackends.Contains(backend)) return ("operational", "");
        if (backend == "not_implemented") return ("unavailable", "declared in the registry but not built - see the rule description");
        return ("unavailable", $"no backend implementing '{backend}'");
    }

    /// <summary>
    /// Per-rule operational state. A rule can be enabled in the policy while the guard that implements it is
    /// switched off elsewhere - the combination that makes a technical file claim a control that inspects nothing.
    /// </summary>
    public IReadOnlyList<BackendHealth> BackendHealthReport() => Rules.Select(r =>
    {
        var (state, note) = BackendState(r.Backend);
        return new BackendHealth(r.Id, r.Title, r.Backend, r.Enabled, state, r.Enabled && state == "operational", note);
    }).ToList();

    /// <summary>Rules switched on whose backend cannot actually enforce them.</summary>
    public IReadOnlyList<BackendHealth> IneffectiveRules() => BackendHealthReport().Where(h => h.RuleEnabled && !h.Effective).ToList();

    // ── evaluation ──────────────────────────────────────────────────────

    /// <summary>Runs every active rule covering <paramref name="scope"/> against <paramref name="text"/>.</summary>
    public ComplianceResult Evaluate(string text, RuleScope scope = RuleScope.Input, EvaluateOptions? options = null)
    {
        options ??= new EvaluateOptions();
        text ??= "";
        var started = Stopwatch.GetTimestamp();
        double Elapsed() => Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        var ctx = new EvalContext { Context = options.Context ?? "", Sources = options.Sources ?? new() };

        if (Options.Status == EngineStatus.Inactive)
            return new ComplianceResult { Allowed = true, Text = text, Decision = "allow", EngineStatus = "inactive", LatencyMs = Elapsed() };

        var findings = new List<Finding>();
        var disclaimers = new List<string>();
        var current = text;
        var blocked = false;
        var staging = Options.Status == EngineStatus.Staging;

        foreach (var rule in ActiveRules(scope).ToList())
        {
            // Detection runs against the original payload so every control reports independently; only
            // transforming backends see the accumulated text, so successive redactions still compose.
            var subject = Transforming.Contains(rule.Backend) ? current : text;
            Detection d;
            try
            {
                d = RunBackend(rule, subject, ctx);
            }
            catch (NotImplementedException ex)
            {
                // A rule the registry promises but nothing implements must be visible, never silently "clean".
                findings.Add(new Finding(rule.Id, rule.Title, rule.Category.Wire(), rule.RiskLevel.Wire(), "log_only",
                    "rule not implemented", null, ex.Message));
                continue;
            }
            catch (Exception ex)
            {
                // A guard failing is itself a compliance event.
                var failClosed = Options.Fallback == FallbackPolicy.FailClosed && FailClosedCategories.Contains(rule.Category);
                var warnPass = Options.Fallback == FallbackPolicy.WarnAndPass;
                findings.Add(new Finding(rule.Id, rule.Title, rule.Category.Wire(), rule.RiskLevel.Wire(),
                    failClosed ? "block" : warnPass ? "warn" : "log_only", "backend failed", null,
                    ex.Message.Length > 200 ? ex.Message[..200] : ex.Message));
                if (failClosed && !staging) blocked = true;
                else if (warnPass && !staging)
                    disclaimers.Add($"[{rule.Title}] could not be evaluated - this response was not checked against that control.");
                continue;
            }

            if (!d.Fired) continue;
            findings.Add(new Finding(rule.Id, rule.Title, rule.Category.Wire(), rule.RiskLevel.Wire(), rule.Action.Wire(), d.Detail, d.Categories));

            // Staging evaluates and records everything but changes nothing.
            if (staging) continue;

            switch (rule.Action)
            {
                case RuleAction.Block:
                    blocked = true;
                    break;
                case RuleAction.Redact:
                    if (d.Replacement is not null) current = d.Replacement;
                    else
                        // Detected, but the backend had nothing masked to put in its place. A visible disclaimer is
                        // the honest outcome: silently doing nothing would let the audit trail record a redaction
                        // that never happened.
                        disclaimers.Add($"[{rule.Title}] detected but not redacted - {d.Detail}");
                    break;
                case RuleAction.Warn:
                    if (rule.Backend == "ai_transparency_notice")
                        disclaimers.Add(new AiTransparencyNotice { Language = Options.Language }.GetMessage());
                    else
                        disclaimers.Add($"[{rule.Title}] {d.Detail}");
                    break;
            }
        }

        var decision = blocked ? "block" : current != text ? "redact" : disclaimers.Count > 0 ? "warn" : "allow";
        var latency = Elapsed();
        var outText = blocked ? text : current;

        JsonObject? entry = null;
        if (options.WriteAudit)
        {
            var arr = new JsonArray();
            foreach (var f in findings) arr.Add(f.ToJson());
            entry = Audit.Record(scope.Wire(), decision, arr,
                requestHash: AuditTrail.TextFingerprint(text),
                // The text as it leaves the gate: differs from request_hash whenever a redaction rewrote it.
                responseHash: AuditTrail.TextFingerprint(outText),
                userId: options.UserId, clientIp: options.ClientIp, requestId: options.RequestId, model: options.Model,
                sources: ctx.Sources, latencyMs: latency);
        }

        return new ComplianceResult
        {
            Allowed = !blocked, Text = outText, Decision = decision, Findings = findings, Disclaimers = disclaimers,
            LatencyMs = latency, EngineStatus = Wire(Options.Status), AuditEntry = entry,
        };
    }

    /// <summary>
    /// The organisation-level system instructions to inject ahead of a model call. Recording them here means
    /// a change made by editing the configuration is captured the first time it is used.
    /// </summary>
    public string ActiveInstructions()
    {
        var text = (Options.SystemPromptOverride ?? "").Trim();
        if (text.Length > 0) Instructions.Record(text);
        return text;
    }

    public void Dispose() => _privacy.Dispose();
}
