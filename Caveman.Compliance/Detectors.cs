// ------------------------------------------------------------------------------
// Caveman.Compliance
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
//
// Detectors for the compliance controls. Port of Synthelion's compliance/detectors.py.
//
// What these are, stated plainly: lexicons, patterns and structural checks - not classifiers.
// Content moderation and factuality are areas where a trained model outperforms a lexicon, and
// nothing here pretends otherwise. What they give is a real, deterministic, explainable control
// with a documented recall limit. Each is biased towards precision over recall: a gate that
// blocks legitimate work gets switched off within a week and then protects nothing.
// ------------------------------------------------------------------------------
using System.Text;
using System.Text.RegularExpressions;

namespace Caveman.Compliance;

/// <summary>Outcome of one detector: whether it fired, why, and (for redacting detectors) the rewritten text.</summary>
public readonly record struct Detection(bool Fired, string Detail, IReadOnlyList<string> Categories, string? Replacement = null)
{
    public static readonly Detection None = new(false, "", Array.Empty<string>());
    public static Detection Hit(string detail, params string[] categories) => new(true, detail, categories);
}

public static class ComplianceDetectors
{
    private const RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    private static Regex Rx(string pattern, RegexOptions extra = RegexOptions.None) =>
        new(pattern, Opt | extra | RegexOptions.Compiled, Timeout);

    private static string Alternation(IEnumerable<string> terms) => string.Join("|", terms.Select(Regex.Escape));

    // ── Toxicity and hate speech ──────────────────────────────────────────
    // Slurs are deliberately not enumerated in source; a deployment that needs them supplies them as a
    // custom rule, where they can be maintained privately.

    private static readonly string[] AbuseTerms =
    {
        "idiot", "moron", "imbecile", "scum", "vermin", "worthless", "pathetic", "disgusting",
        "stupid bitch", "shut the fuck up", "fuck you", "piece of shit",
        "cretino", "idiota", "imbecille", "coglione", "bastardo", "schifoso",
    };
    private static readonly Regex AbuseRx = Rx(@"\b(" + Alternation(AbuseTerms) + @")\b");
    private static readonly Regex HarassmentRx = Rx(
        @"\b(?:i\s+hope\s+you\s+(?:die|suffer|rot)|you\s+(?:should|deserve\s+to)\s+(?:die|kill\s+yourself)|kill\s+yourself|" +
        @"(?:all|those)\s+\w+\s+(?:are|should\s+be)\s+(?:exterminated|eliminated|wiped\s+out)|spero\s+che\s+(?:tu\s+)?(?:muoia|soffra))\b");
    private static readonly Regex GroupRx = Rx(
        @"\b(?:muslims?|jews?|christians?|blacks?|asians?|women|men|gays?|lesbians?|immigrants?|refugees?|disabled|musulmani|ebrei|neri|immigrati|donne)\b");
    private static readonly Regex HostileRx = Rx(
        @"\b(?:are\s+all\s+\w+|should\s+(?:be\s+)?(?:banned|deported|removed|killed)|don'?t\s+deserve|are\s+(?:inferior|subhuman|animals|parasites)|vanno\s+(?:cacciati|eliminati)|sono\s+tutti)\b");

    /// <summary>Abusive language, harassment and targeting of protected groups.</summary>
    public static Detection Toxicity(string? text)
    {
        if (string.IsNullOrEmpty(text)) return Detection.None;
        var cats = new List<string>();
        if (HarassmentRx.IsMatch(text)) cats.Add("harassment");
        if (AbuseRx.IsMatch(text)) cats.Add("abusive_language");
        // Hate speech needs both halves: a group term alone is ordinary discussion.
        if (GroupRx.IsMatch(text) && HostileRx.IsMatch(text)) cats.Add("hate_speech");
        return cats.Count == 0 ? Detection.None : Detection.Hit("matched: " + string.Join(", ", cats), cats.ToArray());
    }

    // ── Hazardous and illegal activity ────────────────────────────────────

    private static readonly Regex IntentRx = Rx(
        @"\b(?:how\s+(?:do\s+i|to|can\s+i)|step[-\s]by[-\s]step|instructions?\s+(?:for|to)|teach\s+me\s+(?:how\s+)?to|guide\s+(?:for|to)\s+making|come\s+(?:si\s+)?(?:fa|faccio|posso)|istruzioni\s+per)\b");
    private static readonly Regex HazardRx = Rx(
        @"\b(?:(?:build|make|construct|assemble|synthesi[sz]e|manufacture|cook)\s+(?:an?\s+|the\s+)?(?:bomb|explosive|ied|pipe\s*bomb|molotov|firearm|silencer|meth|methamphetamine|fentanyl|nerve\s+agent|ricin|sarin)|untraceable\s+(?:gun|firearm|weapon)|ghost\s+gun|(?:bomba|esplosivo|ordigno|droga\s+sintetica))\b");
    private static readonly Regex SelfHarmRx = Rx(
        @"\b(?:how\s+to\s+(?:kill\s+myself|commit\s+suicide|end\s+my\s+life)|painless\s+(?:suicide|way\s+to\s+die)|suicide\s+methods?|come\s+(?:suicidarsi|farla\s+finita))\b");
    private static readonly Regex AskRx = Rx(@"\b(?:for\s+me|please|can\s+you)\b");

    /// <summary>Requests for weapons, controlled substances or self-harm instructions.</summary>
    public static Detection IllegalActivity(string? text)
    {
        if (string.IsNullOrEmpty(text)) return Detection.None;
        var cats = new List<string>();
        if (SelfHarmRx.IsMatch(text)) cats.Add("self_harm");
        if (HazardRx.IsMatch(text) && (IntentRx.IsMatch(text) || AskRx.IsMatch(text))) cats.Add("hazardous_instructions");
        return cats.Count == 0 ? Detection.None : Detection.Hit("matched: " + string.Join(", ", cats), cats.ToArray());
    }

    // ── Health data (PHI) ─────────────────────────────────────────────────

    private static readonly string[] ClinicalTerms =
    {
        "diagnosis", "diagnosed", "prognosis", "symptoms", "treatment", "therapy", "medication", "prescription",
        "dosage", "biopsy", "chemotherapy", "hiv", "aids", "cancer", "tumour", "tumor", "diabetes", "hepatitis",
        "psychiatric", "depression", "schizophrenia", "pregnancy", "blood test", "medical record", "patient", "clinical",
        "diagnosi", "prognosi", "terapia", "farmaco", "referto", "cartella clinica", "paziente", "gravidanza", "tumore", "depressione",
    };
    private static readonly Regex ClinicalRx = Rx(@"\b(" + Alternation(ClinicalTerms) + @")\b");
    private static readonly Regex PersonMarkerRx = Rx(@"\b(?:patient|paziente|mr\.?|mrs\.?|ms\.?|sig\.?)\b");
    private static readonly Regex PersonNameRx = new(@"\b\p{Lu}\p{Ll}+\s+\p{Lu}\p{Ll}+\b", RegexOptions.Compiled, Timeout);

    /// <summary>
    /// Clinical content tied to an identifiable person, plus a masked version. Requires both halves on
    /// purpose: a medical article is not PHI, and a name on its own is ordinary PII already handled by
    /// PrivacyGuard. Returns the redacted text because the rule's action is REDACT.
    /// </summary>
    public static Detection Phi(string? text)
    {
        if (string.IsNullOrEmpty(text)) return Detection.None;
        var terms = ClinicalRx.Matches(text).Select(m => m.Value.ToLowerInvariant()).ToHashSet();
        if (terms.Count == 0) return Detection.None;
        if (!PersonMarkerRx.IsMatch(text) && !PersonNameRx.IsMatch(text)) return Detection.None;
        var masked = ClinicalRx.Replace(text, "[HEALTH]");
        return new Detection(true, $"{terms.Count} clinical term(s) beside a person reference", new[] { "health_data" }, masked);
    }

    // ── Cross-border transfer / data residency ────────────────────────────

    // Host suffixes whose processing location is documented as inside the EEA. Everything else is treated
    // as a third-country transfer: "unknown" and "outside the EEA" carry the same obligation under GDPR Chapter V.
    private static readonly string[] EeaSuffixes =
    {
        ".eu", ".europa.eu", ".de", ".fr", ".it", ".es", ".nl", ".be", ".ie", ".se", ".fi", ".dk", ".at", ".pl", ".pt", ".cz", ".gr", ".no", ".is",
    };
    private static readonly Regex UrlRx = Rx(@"https?://[^\s""'<>)\]]+");

    /// <summary>
    /// Flags endpoints that would take data outside the EEA. A host on <paramref name="allowedHosts"/> is
    /// accepted regardless of suffix - that is where an operator records a provider covered by standard
    /// contractual clauses.
    /// </summary>
    public static Detection DataResidency(string? text, IEnumerable<string>? allowedHosts = null)
    {
        if (string.IsNullOrEmpty(text)) return Detection.None;
        var allowed = (allowedHosts ?? Array.Empty<string>()).Select(a => a.ToLowerInvariant()).ToList();
        var offending = new SortedSet<string>(StringComparer.Ordinal);
        foreach (Match m in UrlRx.Matches(text))
        {
            if (!Uri.TryCreate(m.Value, UriKind.Absolute, out var uri)) continue;
            var host = uri.Host.ToLowerInvariant();
            if (host is "" or "localhost" or "127.0.0.1") continue;
            if (allowed.Any(a => host == a || host.EndsWith("." + a, StringComparison.Ordinal))) continue;
            if (EeaSuffixes.Any(s => host.EndsWith(s, StringComparison.Ordinal))) continue;
            offending.Add(host);
        }
        return offending.Count == 0
            ? Detection.None
            : Detection.Hit("endpoint(s) outside the EEA allow-list: " + string.Join(", ", offending.Take(5)), "third_country_transfer");
    }

    // ── Code vulnerability patterns ───────────────────────────────────────

    private static readonly (string Name, Regex Rx)[] VulnPatterns =
    {
        ("rce_eval", Rx(@"\b(?:eval|exec)\s*\(\s*(?:input|request|req|params|argv|sys\.argv)")),
        ("shell_injection", Rx(@"\b(?:os\.system|subprocess\.(?:call|run|Popen))\s*\([^)]*(?:\+|%|\.format|f"")")),
        ("shell_true", Rx(@"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True")),
        ("sql_concat", Rx(@"(?:SELECT|INSERT|UPDATE|DELETE)\b[^;""']*[""']\s*(?:\+|%|\.format|\|\|)")),
        ("deserialisation", Rx(@"\b(?:pickle\.loads|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads)")),
        ("weak_hash", Rx(@"\bhashlib\.(?:md5|sha1)\s*\(")),
        ("hardcoded_secret", Rx(@"\b(?:password|passwd|secret|api_key)\s*=\s*[""'][^""']{6,}[""']")),
        ("tls_verify_off", Rx(@"verify\s*=\s*False|rejectUnauthorized\s*:\s*false")),
        ("xss_innerhtml", Rx(@"\.innerHTML\s*=\s*(?!['""]\s*['""])")),
    };

    /// <summary>Well-known dangerous code shapes (a subset of the OWASP Top 10). Not a substitute for a SAST tool.</summary>
    public static Detection CodeVulnerabilities(string? text)
    {
        if (string.IsNullOrEmpty(text)) return Detection.None;
        var hits = VulnPatterns.Where(p => p.Rx.IsMatch(text)).Select(p => p.Name).ToArray();
        return hits.Length == 0 ? Detection.None : Detection.Hit($"{hits.Length} pattern(s): {string.Join(", ", hits)}", hits);
    }

    // ── Copyright / licence ───────────────────────────────────────────────

    private static readonly Regex LicenceRx = Rx(
        @"(?:\b(?:GNU\s+GENERAL\s+PUBLIC\s+LICENSE|GPL-[23]\.0|AGPL-3\.0|Creative\s+Commons\s+Attribution|CC\s+BY-NC|All\s+rights\s+reserved|Copyright\s+\(c\)\s*\d{4})|©\s*\d{4})");

    /// <summary>Licence headers and copyright notices. Detects a declared notice, not an unmarked copied passage.</summary>
    public static Detection Copyright(string? text)
    {
        if (string.IsNullOrEmpty(text)) return Detection.None;
        var hits = LicenceRx.Matches(text).Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.Ordinal).ToList();
        return hits.Count == 0 ? Detection.None : Detection.Hit("licence/copyright notice present: " + string.Join(", ", hits.Take(3)), "copyright_notice");
    }

    // ── Grounding / hallucination ─────────────────────────────────────────

    private static readonly Regex WordRx = new(@"\b\w{4,}\b", RegexOptions.Compiled, Timeout);

    /// <summary>
    /// How much of the answer is anchored in the supplied context (lexical overlap, not entailment).
    /// Returns not-fired when no context was supplied: with nothing to check against, silence is the
    /// only honest result.
    /// </summary>
    public static Detection Ungrounded(string? text, string? context, double minOverlap = 0.35)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(context)) return Detection.None;
        var answer = WordRx.Matches(text).Select(m => m.Value.ToLowerInvariant()).ToHashSet();
        if (answer.Count == 0) return Detection.None;
        var ctx = WordRx.Matches(context).Select(m => m.Value.ToLowerInvariant()).ToHashSet();
        var overlap = answer.Count(w => ctx.Contains(w)) / (double)answer.Count;
        return overlap >= minOverlap
            ? Detection.None
            : Detection.Hit($"only {overlap:P0} of the answer's terms appear in the supplied context (threshold {minOverlap:P0})", "ungrounded_output");
    }

    // ── Machine-readable marking (AI Act Art. 50(2)) ──────────────────────

    // Unicode TAG block: a documented, machine-readable, visually invisible channel that survives
    // copy/paste of plain text. A marking, not a robust watermark: anything that normalises Unicode strips it.
    private const int TagBase = 0xE0000;
    private const string MarkerPrefix = "CAVEMAN1:";

    /// <summary>Appends an invisible, machine-readable marker to generated content.</summary>
    public static string EmbedContentMarker(string? text, string marker = "AI-GENERATED")
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var sb = new StringBuilder(text);
        foreach (var c in MarkerPrefix + marker)
            if (c is >= (char)0x20 and <= (char)0x7E) sb.Append(char.ConvertFromUtf32(TagBase + c));
        return sb.ToString();
    }

    /// <summary>Reads back a marker embedded by <see cref="EmbedContentMarker"/>, if present.</summary>
    public static string? ExtractContentMarker(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        var sb = new StringBuilder();
        for (var i = 0; i < text.Length; i++)
        {
            if (!char.IsHighSurrogate(text[i]) || i + 1 >= text.Length) continue;
            var cp = char.ConvertToUtf32(text[i], text[i + 1]);
            if (cp >= TagBase + 0x20 && cp <= TagBase + 0x7E) sb.Append((char)(cp - TagBase));
            i++;
        }
        var decoded = sb.ToString();
        return decoded.StartsWith(MarkerPrefix, StringComparison.Ordinal) ? decoded[MarkerPrefix.Length..] : null;
    }

    /// <summary>Fires when generated output carries no machine-readable marking.</summary>
    public static Detection MissingMarker(string? text)
    {
        if (string.IsNullOrEmpty(text)) return Detection.None;
        return ExtractContentMarker(text) is not null
            ? Detection.None
            : Detection.Hit("generated content carries no machine-readable AI marking", "unmarked_output");
    }

    // ── Output sanitisation ───────────────────────────────────────────────

    private static readonly Regex ScriptRx = Rx(@"<script\b.*?</script\s*>", RegexOptions.Singleline);
    private static readonly Regex ActiveTagRx = Rx(@"<\s*(iframe|object|embed)\b[^>]*>.*?<\s*/\s*\1\s*>", RegexOptions.Singleline);
    private static readonly Regex EventAttrRx = Rx(@"\son\w+\s*=\s*(""[^""]*""|'[^']*'|[^\s>]+)");

    /// <summary>Strips script tags, active embeds and inline event handlers.</summary>
    public static Detection SanitiseOutput(string text)
    {
        var cleaned = ScriptRx.Replace(text, "");
        cleaned = ActiveTagRx.Replace(cleaned, "");
        cleaned = EventAttrRx.Replace(cleaned, "");
        return cleaned == text
            ? Detection.None
            : new Detection(true, "removed active markup from output", new[] { "active_markup" }, cleaned);
    }
}
