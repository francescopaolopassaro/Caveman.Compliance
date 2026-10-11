// ------------------------------------------------------------------------------
// Caveman.Compliance
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
//
// Compact security guards used by the compliance backends: a secrets scanner (Synthelion's
// EnterpriseGuard content categories and sensitive_guard), a destructive-command matcher
// (safety_guard) and the per-agent-type policy packs (agent_policy). Detection only; the engine
// decides what to do with a hit.
// ------------------------------------------------------------------------------
using System.Text.RegularExpressions;

namespace Caveman.Compliance;

/// <summary>Credential-shaped content: cloud keys, tokens, private keys, connection strings.</summary>
public static class SecretScanner
{
    private const RegexOptions Opt = RegexOptions.CultureInvariant | RegexOptions.Compiled;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);
    private const int ScanWindow = 64 * 1024;
    private const int Overlap = 1024;

    private static Regex Rx(string p, bool ignoreCase = false) =>
        new(p, ignoreCase ? Opt | RegexOptions.IgnoreCase : Opt, Timeout);

    /// <summary>A named detector and the EnterpriseGuard-style category it belongs to.</summary>
    public sealed record Pattern(string Category, string Name, Regex Rx);

    public static readonly IReadOnlyList<Pattern> Patterns = new[]
    {
        new Pattern("private_keys", "PEM private key block", Rx(@"-----BEGIN[\s\S]*?PRIVATE KEY-----")),
        new Pattern("cloud_credentials", "AWS access key", Rx(@"(?<![A-Z0-9])AKIA[A-Z0-9]{16,}(?![A-Z0-9])")),
        new Pattern("cloud_credentials", "AWS secret access key", Rx(@"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*=\s*[A-Za-z0-9/+=]{30,}")),
        new Pattern("cloud_credentials", "Azure storage connection string", Rx(@"DefaultEndpointsProtocol=[^;]+;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}", true)),
        new Pattern("cloud_credentials", "Azure SAS token", Rx(@"[?&]sig=[A-Za-z0-9%]{20,}")),
        new Pattern("cloud_credentials", "GCP service account key", Rx(@"""type""\s*:\s*""service_account""[\s\S]{0,400}""private_key""\s*:\s*""-----BEGIN")),
        new Pattern("ftp_credentials", "FTP/SFTP URL with embedded credentials", Rx(@"\b(?:ftp|sftp)://[^\s:@/]+:[^\s@/]+@[^\s/]+", true)),
        new Pattern("database_connections", "Database connection URL with embedded credentials",
            Rx(@"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|mssql|oracle)://[^\s:@/]+:[^\s@/]+@[^\s/]+", true)),
        new Pattern("database_connections", "ADO.NET connection string",
            Rx(@"(?:Server|Data Source)\s*=\s*[^;]+;[^;]*;?\s*(?:User Id|Uid|User)\s*=\s*[^;]+;\s*Password\s*=\s*[^;]+", true)),
        new Pattern("database_connections", "JDBC connection string", Rx(@"\bjdbc:[a-z0-9]+://[^\s'""]+", true)),
        new Pattern("git_credentials", "Git remote URL with embedded credentials",
            Rx(@"\bhttps?://[^\s:@/]+:[^\s@/]+@(?:github\.com|gitlab\.com|bitbucket\.org|[a-z0-9.-]+\.git[a-z]*)", true)),
        new Pattern("api_tokens", "GitHub token", Rx(@"\bghp_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
        new Pattern("api_tokens", "Slack token", Rx(@"\bxox[bp]-[A-Za-z0-9-]{10,}\b")),
        new Pattern("api_tokens", "API secret key", Rx(@"(?<![A-Za-z])sk-[A-Za-z0-9]{20,}\b")),
        new Pattern("api_tokens", "Bearer token", Rx(@"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}")),
    };

    private static readonly string[] DotEnvMarkers = { "SECRET", "TOKEN", "PASSWORD", "APIKEY", "API_KEY" };
    private static readonly Regex DotEnvLine = Rx(@"^([A-Z0-9_]+)=(.+)$");

    /// <summary>Three or more KEY=value lines whose key mentions SECRET/TOKEN/PASSWORD/APIKEY - the shape of a .env dump.</summary>
    private static bool HasBulkDotEnv(string text)
    {
        var count = 0;
        foreach (var raw in text.Split('\n'))
        {
            var m = DotEnvLine.Match(raw.Trim());
            if (!m.Success || m.Groups[2].Value.Trim().Length == 0) continue;
            if (DotEnvMarkers.Any(k => m.Groups[1].Value.Contains(k, StringComparison.Ordinal)) && ++count >= 3) return true;
        }
        return false;
    }

    /// <summary>
    /// Scans the whole text in overlapping 64 KiB windows (a secret past the first window, or straddling
    /// a window edge, is still found). Returns the first match, or <c>null</c>.
    /// </summary>
    public static (string Category, string Name)? Find(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        for (var start = 0; start < text.Length; start += ScanWindow - Overlap)
        {
            var window = text.Substring(start, Math.Min(ScanWindow, text.Length - start));
            foreach (var p in Patterns)
                if (p.Rx.IsMatch(window)) return (p.Category, p.Name);
            if (start + ScanWindow >= text.Length) break;
        }
        return HasBulkDotEnv(text) ? ("dotenv_dump", "bulk .env secrets") : null;
    }
}

/// <summary>Destructive shell / SQL / git commands.</summary>
public static class DestructiveCommands
{
    private static readonly string[] Patterns =
    {
        "rm -rf", "del /f", "format ", "mkfs", "dd if=", "> /dev/sda", "> /dev/sd", "drop database", "drop table",
        "truncate table", "delete from", "shutdown", "reboot", "chmod 777", "chown -r", "git push --force",
        "git reset --hard", ">|", ":!q", ":w!", "cargo clean", "npm cache clean", "docker rmi -f", "docker system prune -a",
    };

    // Word-boundary-aware where the pattern starts/ends with an alphanumeric, so "format " style matches
    // do not fire inside longer words, while command strings like "rm -rf" or "> /dev/sda" match by content.
    private static readonly List<(string Pattern, Regex Rx)> Matchers = Patterns.Select(p =>
    {
        var left = char.IsLetterOrDigit(p[0]) ? "(?<![A-Za-z0-9])" : "";
        var right = char.IsLetterOrDigit(p[^1]) ? "(?![A-Za-z0-9])" : "";
        return (p, new Regex(left + Regex.Escape(p) + right, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromSeconds(1)));
    }).ToList();

    /// <summary>The first destructive pattern found in <paramref name="text"/>, or <c>null</c>.</summary>
    public static string? Find(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        foreach (var (pattern, rx) in Matchers)
            if (rx.IsMatch(text)) return pattern;
        return null;
    }
}

/// <summary>Outcome of an agent-policy check.</summary>
public enum PolicyVerdict { Allow, Gate, Block }

public sealed record PolicyDecision(PolicyVerdict Verdict, string? Requirement = null, string? RuleName = null, string? Reason = null)
{
    public bool Allowed => Verdict == PolicyVerdict.Allow;
}

/// <summary>
/// Per-agent-type guardrail policy: a baseline applied to every agent plus a rule pack per profile
/// (dev, support, rag, data, ops, browser). Three outcomes: allow, block, or <b>gate</b> - legitimate but
/// needing explicit human approval. Every rule carries the requirement id it implements.
/// </summary>
public static class AgentPolicy
{
    public static readonly IReadOnlyList<string> Profiles = new[] { "base", "dev", "support", "rag", "data", "ops", "browser" };

    private sealed record PolicyRule(string Requirement, string Name, Regex Rx, PolicyVerdict Verdict, string Reason);

    private static PolicyRule R(string req, string name, string pattern, PolicyVerdict v, string reason) =>
        new(req, name, new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromSeconds(1)), v, reason);

    private static readonly PolicyRule[] Base =
    {
        R("REQ-BASE-02", "recursive delete", @"\brm\s+(-[a-z]*[rf][a-z]*\s+)+/?\S*", PolicyVerdict.Block, "Recursive delete is blocked for every agent profile."),
        R("REQ-BASE-02", "disk overwrite", @"\b(mkfs|dd)\b[^|;]*\bof=/dev/", PolicyVerdict.Block, "Writing directly to a block device is blocked."),
        R("REQ-BASE-02", "remote script piped to shell", @"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba)?sh", PolicyVerdict.Block, "Piping a downloaded script straight into a shell is blocked."),
        R("REQ-BASE-02", "history/credential file read", @"\b(cat|less|more|head|tail|type)\b[^|;]*(\.bash_history|\.zsh_history|shadow|id_rsa|\.aws/credentials)", PolicyVerdict.Block, "Reading credential or shell-history files is blocked."),
    };

    private static readonly Dictionary<string, PolicyRule[]> Packs = new(StringComparer.OrdinalIgnoreCase)
    {
        ["dev"] = new[]
        {
            R("REQ-DEV-02", "git force push", @"\bgit\s+push\b[^|;]*(--force\b(?!-with-lease)|(?<![\w-])-f(?![\w-]))", PolicyVerdict.Gate, "Force push rewrites published history - explicit approval required."),
            R("REQ-DEV-02", "git history rewrite", @"\bgit\s+(reset\s+--hard|rebase\b[^|;]*--root|filter-branch|filter-repo)\b", PolicyVerdict.Gate, "Rewriting git history requires explicit approval."),
            R("REQ-DEV-01", "branch deletion on remote", @"\bgit\s+push\b[^|;]*(--delete|:\s*\w)", PolicyVerdict.Gate, "Deleting a remote branch requires explicit approval."),
            R("REQ-DEV-03", "public PR from private issue", @"\bgh\s+pr\s+create\b[^|;]*(--public|--repo\s+\S+)", PolicyVerdict.Gate, "Opening a PR on another repo can carry internal context outward - approval required."),
        },
        ["support"] = new[]
        {
            R("REQ-SUPP-03", "bulk customer export", @"\b(export|download)\b[^|;]*\b(all_customers|customers|users)\b[^|;]*\b(csv|json|xlsx|dump)\b", PolicyVerdict.Gate, "Bulk customer export requires explicit approval."),
            R("REQ-SUPP-03", "account access change", @"\b(reset_password|change_email|disable_2fa|disable_mfa|transfer_ownership)\b", PolicyVerdict.Gate, "Changing a customer's account access requires explicit approval."),
        },
        ["rag"] = new[]
        {
            R("REQ-RAG-01", "non-http scheme", @"\b(file|ftp|gopher|dict|ldap|tftp|jar|netdoc)://", PolicyVerdict.Block, "Only http:// and https:// may be fetched."),
        },
        ["data"] = new[]
        {
            R("REQ-DATA-01", "destructive DDL", @"\b(drop\s+(table|database|schema)|truncate\s+table)\b", PolicyVerdict.Block, "DROP/TRUNCATE is blocked for analytics agents."),
            R("REQ-DATA-01", "credential table read", @"\bfrom\s+\W?(users?_credentials|credentials|secrets|api_keys|auth_tokens|passwords)\W?\b", PolicyVerdict.Block, "Reading credential tables is blocked."),
            R("REQ-DATA-02", "unscoped delete/update", @"\b(delete\s+from|update)\s+\w+(?![\s\S]*\bwhere\b)", PolicyVerdict.Gate, "A DELETE/UPDATE without a WHERE clause requires explicit approval."),
            R("REQ-DATA-02", "scoped delete/update", @"\b(delete\s+from|update)\s+\w+[\s\S]*\bwhere\b", PolicyVerdict.Gate, "Data modification requires explicit approval."),
        },
        ["ops"] = new[]
        {
            R("REQ-OPS-01", "terraform destroy", @"\bterraform\s+destroy\b", PolicyVerdict.Block, "Destroying infrastructure is blocked."),
            R("REQ-OPS-01", "kubernetes mass delete", @"\bkubectl\s+delete\b[^|;]*(--all\b|\bnamespace\b)", PolicyVerdict.Block, "Deleting a namespace or all resources is blocked."),
            R("REQ-OPS-01", "cloud resource deletion", @"\b(aws|az|gcloud)\b[^|;]*\b(delete|destroy|terminate|rm)\b", PolicyVerdict.Gate, "Deleting a cloud resource requires explicit approval."),
            R("REQ-OPS-02", "terraform apply", @"\bterraform\s+apply\b", PolicyVerdict.Gate, "`terraform apply` changes live infrastructure - approval required."),
            R("REQ-OPS-02", "IAM escalation", @"\b(attach-(role|user)-policy|add-iam-policy-binding|create-role-binding|AdministratorAccess|roles/owner)\b", PolicyVerdict.Gate, "Granting IAM privileges requires explicit approval."),
            R("REQ-OPS-02", "production secret read", @"\b(vault\s+(kv\s+)?get|secretsmanager\s+get-secret-value|kubectl\s+get\s+secret)\b", PolicyVerdict.Gate, "Reading a production secret requires explicit approval."),
        },
        ["browser"] = new[]
        {
            R("REQ-BROWSER-01", "browser storage read", @"\b(document\.cookie|localStorage|sessionStorage|indexedDB)\b", PolicyVerdict.Block, "Reading cookies or browser storage is blocked."),
            R("REQ-BROWSER-01", "credential typing", @"\b(password|passwd|otp|2fa|cvv|card[_\s-]?number)\b", PolicyVerdict.Block, "The agent must not type credentials - hand control to the user."),
            R("REQ-BROWSER-02", "financial/irreversible click", @"\b(place\s+order|confirm\s+payment|buy\s+now|pay\s+now|delete\s+account|transfer\s+funds|checkout)\b", PolicyVerdict.Gate, "Financial or irreversible actions require explicit confirmation."),
        },
    };

    /// <summary>Baseline rules plus the profile's own; an unknown profile still gets the baseline.</summary>
    public static PolicyDecision Check(string profile, string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return new PolicyDecision(PolicyVerdict.Allow);
        var rules = Base.Concat(Packs.TryGetValue(profile ?? "base", out var pack) ? pack : Array.Empty<PolicyRule>());
        PolicyDecision? gate = null;
        foreach (var r in rules)
        {
            if (!r.Rx.IsMatch(text)) continue;
            var decision = new PolicyDecision(r.Verdict, r.Requirement, r.Name, r.Reason);
            if (r.Verdict == PolicyVerdict.Block) return decision;   // a block outranks a gate
            gate ??= decision;
        }
        return gate ?? new PolicyDecision(PolicyVerdict.Allow);
    }
}
