// ------------------------------------------------------------------------------
// Caveman.Compliance
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
//
// Tamper-evident audit trail for compliance decisions (EU AI Act Art. 12) and the system-instruction
// version registry. Port of Synthelion's compliance/audit.py and instructions.py.
//
// Each entry carries the hash of the one before it, so the log is a chain: an entry edited or removed
// after the fact breaks every link after it, and VerifyChain() reports exactly where. This is
// tamper-EVIDENT, not tamper-proof - anyone who can write the file can rewrite the whole chain. Real
// immutability needs an append-only medium or an external notary; what this gives an auditor is the
// ability to prove the log has not been quietly edited in place.
// ------------------------------------------------------------------------------
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Caveman.Compliance;

/// <summary>Result of walking the audit chain.</summary>
public sealed record ChainVerification(bool Valid, int Entries, int? BrokenAt = null, string Reason = "")
{
    public JsonObject ToJson() => new()
    {
        ["valid"] = Valid, ["entries"] = Entries, ["broken_at"] = BrokenAt, ["reason"] = Reason,
    };
}

internal static class Canonical
{
    /// <summary>Compact JSON with object keys sorted, so a digest does not depend on property order.</summary>
    public static string Json(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(sb, node);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, JsonNode? node)
    {
        switch (node)
        {
            case null: sb.Append("null"); break;
            case JsonObject o:
                sb.Append('{');
                var first = true;
                foreach (var kv in o.OrderBy(k => k.Key, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append(JsonSerializer.Serialize(kv.Key)).Append(':');
                    Write(sb, kv.Value);
                }
                sb.Append('}');
                break;
            case JsonArray a:
                sb.Append('[');
                for (var i = 0; i < a.Count; i++) { if (i > 0) sb.Append(','); Write(sb, a[i]); }
                sb.Append(']');
                break;
            default:
                sb.Append(node.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
                break;
        }
    }

    public static string Sha256(string text)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text ?? ""));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>Aggregates for the executive report.</summary>
public sealed class AuditStatistics
{
    public int TotalCalls { get; init; }
    public int CallsWithFindings { get; init; }
    public double ViolationRatePct { get; init; }
    public Dictionary<string, int> ByCategory { get; init; } = new();
    public Dictionary<string, int> ByRiskLevel { get; init; } = new();
    public Dictionary<string, int> ByDecision { get; init; } = new();
    public Dictionary<string, int> ByRule { get; init; } = new();
    public double LatencyAvgMs { get; init; }
    public double LatencyP95Ms { get; init; }
    public double LatencyMaxMs { get; init; }

    private static JsonObject Counts(Dictionary<string, int> d)
    {
        var o = new JsonObject();
        foreach (var kv in d.OrderByDescending(k => k.Value).ThenBy(k => k.Key, StringComparer.Ordinal)) o[kv.Key] = kv.Value;
        return o;
    }

    public JsonObject ToJson() => new()
    {
        ["total_calls"] = TotalCalls,
        ["calls_with_findings"] = CallsWithFindings,
        ["violation_rate_pct"] = ViolationRatePct,
        ["by_category"] = Counts(ByCategory),
        ["by_risk_level"] = Counts(ByRiskLevel),
        ["by_decision"] = Counts(ByDecision),
        ["by_rule"] = Counts(ByRule),
        ["latency_ms"] = new JsonObject { ["avg"] = LatencyAvgMs, ["p95"] = LatencyP95Ms, ["max"] = LatencyMaxMs },
    };
}

/// <summary>Hash-chained, append-only JSONL audit trail. Stores fingerprints of payloads, never the text.</summary>
public sealed class AuditTrail
{
    private const string FileName = "compliance_audit.jsonl";
    private static readonly string Genesis = new('0', 64);
    private static readonly object ProcessLock = new();

    public string Directory { get; }
    public string FilePath => Path.Combine(Directory, FileName);

    /// <param name="directory">Folder holding the log; defaults to <c>~/.caveman/compliance</c>.</param>
    public AuditTrail(string? directory = null)
    {
        Directory = directory ?? DefaultDirectory();
    }

    public static string DefaultDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".caveman", "compliance");

    /// <summary>Stable identifier for a payload, safe to store in the audit log.</summary>
    public static string TextFingerprint(string? text) => Canonical.Sha256(text ?? "");

    private static string EntryHash(JsonObject entry)
    {
        var copy = new JsonObject();
        foreach (var kv in entry.Where(k => k.Key != "hash"))
            copy[kv.Key] = kv.Value?.DeepClone();
        return Canonical.Sha256(Canonical.Json(copy));
    }

    public IReadOnlyList<JsonObject> ReadEntries(int? limit = null)
    {
        var path = FilePath;
        var entries = new List<JsonObject>();
        if (!File.Exists(path)) return entries;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs, Encoding.UTF8);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                line = line.Trim();
                if (line.Length == 0) continue;
                try { if (JsonNode.Parse(line) is JsonObject o) entries.Add(o); }
                catch (JsonException) { /* a torn line is skipped, not fatal */ }
            }
        }
        catch (IOException) { return new List<JsonObject>(); }
        return limit is > 0 && entries.Count > limit ? entries.GetRange(entries.Count - limit.Value, limit.Value) : entries;
    }

    private string LastHash()
    {
        var entries = ReadEntries();
        return entries.Count > 0 ? entries[^1]["hash"]?.GetValue<string>() ?? Genesis : Genesis;
    }

    /// <summary>
    /// Appends one decision to the chain and returns the entry written. Deliberately stores a hash of the
    /// processed text, never the text itself: an audit log of prompts would recreate the very exposure the
    /// privacy rules exist to prevent, and would itself become personal data under GDPR.
    /// </summary>
    public JsonObject Record(
        string scope, string decision, JsonArray findings,
        string requestHash = "", string responseHash = "", string userId = "", string clientIp = "",
        string model = "", string requestId = "", IEnumerable<string>? sources = null, double latencyMs = 0)
    {
        var now = DateTimeOffset.UtcNow;
        var srcs = new JsonArray();
        foreach (var s in sources ?? Array.Empty<string>()) srcs.Add(s);

        using var mutex = AcquireMutex();
        lock (ProcessLock)
        {
            var entry = new JsonObject
            {
                ["ts"] = now.ToUnixTimeMilliseconds() / 1000.0,
                ["ts_utc"] = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                // Correlates the decision with the caller's own request logs; generated when not supplied.
                ["request_id"] = string.IsNullOrEmpty(requestId) ? Guid.NewGuid().ToString("N") : requestId,
                ["scope"] = scope,
                ["decision"] = decision,
                ["request_hash"] = requestHash,
                ["response_hash"] = responseHash,
                ["user_id"] = userId,
                ["client_ip"] = clientIp,
                ["model"] = model,
                ["latency_ms"] = Math.Round(latencyMs, 3),
                // Retrieval provenance (AI Act Art. 13): identifiers only, never the retrieved text.
                ["sources"] = srcs,
                ["findings"] = findings,
                ["prev_hash"] = LastHash(),
                ["pid"] = Environment.ProcessId,
            };
            entry["hash"] = EntryHash(entry);
            try
            {
                System.IO.Directory.CreateDirectory(Directory);
                var bytes = Encoding.UTF8.GetBytes(entry.ToJsonString(new JsonSerializerOptions
                {
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                }) + "\n");
                // One write of one line, so concurrent writers cannot interleave inside an entry.
                using var fs = new FileStream(FilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                fs.Write(bytes, 0, bytes.Length);
            }
            catch (IOException) { /* an unwritable log must not take the gateway down */ }
            catch (UnauthorizedAccessException) { }
            return entry;
        }
    }

    // Cross-process guard around read-last-hash + append, so two processes sharing a log cannot both
    // chain onto the same predecessor.
    private IDisposable AcquireMutex()
    {
        try
        {
            var name = "Caveman.Compliance.Audit." + Canonical.Sha256(Path.GetFullPath(FilePath))[..24];
            var m = new Mutex(false, name);
            try { m.WaitOne(TimeSpan.FromSeconds(5)); }
            catch (AbandonedMutexException) { }
            return new MutexScope(m);
        }
        catch { return new NullScope(); }
    }

    private sealed class MutexScope(Mutex m) : IDisposable
    {
        public void Dispose() { try { m.ReleaseMutex(); } catch { } m.Dispose(); }
    }

    private sealed class NullScope : IDisposable { public void Dispose() { } }

    /// <summary>
    /// Walks the chain and reports the first entry that does not line up. Two independent checks per entry:
    /// its recorded prev_hash must match the previous entry's hash (nothing removed or reordered), and its
    /// own hash must match a fresh digest of its content (nothing edited in place).
    /// </summary>
    public ChainVerification VerifyChain()
    {
        var entries = ReadEntries();
        var prev = Genesis;
        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            if (e["prev_hash"]?.GetValue<string>() != prev)
                return new ChainVerification(false, entries.Count, i, "prev_hash does not match the preceding entry - an entry was removed, reordered or inserted");
            if (e["hash"]?.GetValue<string>() != EntryHash(e))
                return new ChainVerification(false, entries.Count, i, "entry hash does not match its content - the entry was edited after it was written");
            prev = e["hash"]!.GetValue<string>();
        }
        return new ChainVerification(true, entries.Count);
    }

    public AuditStatistics Statistics(DateTimeOffset? since = null)
    {
        var entries = ReadEntries().AsEnumerable();
        if (since is { } s)
        {
            var cutoff = s.ToUnixTimeMilliseconds() / 1000.0;
            entries = entries.Where(e => (e["ts"]?.GetValue<double>() ?? 0) >= cutoff);
        }
        var list = entries.ToList();

        var byCat = new Dictionary<string, int>(); var byRisk = new Dictionary<string, int>();
        var byDecision = new Dictionary<string, int>(); var byRule = new Dictionary<string, int>();
        var latencies = new List<double>();

        static void Inc(Dictionary<string, int> d, string k) => d[k] = d.GetValueOrDefault(k) + 1;

        foreach (var e in list)
        {
            Inc(byDecision, e["decision"]?.GetValue<string>() ?? "unknown");
            var lat = e["latency_ms"]?.GetValue<double>() ?? 0;
            if (lat > 0) latencies.Add(lat);
            if (e["findings"] is not JsonArray fs) continue;
            foreach (var f in fs.OfType<JsonObject>())
            {
                Inc(byCat, f["category"]?.GetValue<string>() ?? "unknown");
                Inc(byRisk, f["risk_level"]?.GetValue<string>() ?? "unknown");
                Inc(byRule, f["rule_id"]?.GetValue<string>() ?? "unknown");
            }
        }

        latencies.Sort();
        var total = list.Count;
        var violations = list.Count(e => e["findings"] is JsonArray a && a.Count > 0);
        return new AuditStatistics
        {
            TotalCalls = total,
            CallsWithFindings = violations,
            ViolationRatePct = total > 0 ? Math.Round(violations * 100.0 / total, 2) : 0,
            ByCategory = byCat, ByRiskLevel = byRisk, ByDecision = byDecision, ByRule = byRule,
            LatencyAvgMs = latencies.Count > 0 ? Math.Round(latencies.Average(), 2) : 0,
            LatencyP95Ms = latencies.Count > 0 ? Math.Round(latencies[Math.Min(latencies.Count - 1, (int)(latencies.Count * 0.95))], 2) : 0,
            LatencyMaxMs = latencies.Count > 0 ? Math.Round(latencies[^1], 2) : 0,
        };
    }

    /// <summary>
    /// Signed-style receipt attesting one response cleared every guardrail. The "signature" is the entry's
    /// own chain hash - it proves the attestation belongs to this decision at this position in the log. It is
    /// not a cryptographic signature under a private key; that needs a key-management story this module does not own.
    /// </summary>
    public static JsonObject ConformityReceipt(JsonObject entry) => new()
    {
        ["receipt_version"] = "1",
        ["issued_at"] = entry["ts_utc"]?.DeepClone(),
        ["request_id"] = entry["request_id"]?.DeepClone(),
        ["request_hash"] = entry["request_hash"]?.DeepClone(),
        ["response_hash"] = entry["response_hash"]?.DeepClone(),
        ["decision"] = entry["decision"]?.DeepClone(),
        ["findings"] = (entry["findings"] as JsonArray)?.Count ?? 0,
        ["chain_hash"] = entry["hash"]?.DeepClone(),
        ["attestation"] = "All enabled compliance guardrails were evaluated for this transaction.",
    };
}

/// <summary>
/// System-instruction registry with version history. The organisation-level instructions injected ahead of
/// every model call are a compliance artefact: Annex IV asks for the history of what the model was told, not
/// just the current text. The text itself is stored (unlike the payload hashes in the audit trail) - these
/// are words the operator wrote, not user data.
/// </summary>
public sealed class SystemInstructionRegistry
{
    private const string FileName = "system_instructions.jsonl";
    private static readonly object ProcessLock = new();

    public string Directory { get; }
    public string FilePath => Path.Combine(Directory, FileName);

    public SystemInstructionRegistry(string? directory = null) => Directory = directory ?? AuditTrail.DefaultDirectory();

    private static string Digest(string text) => Canonical.Sha256(text ?? "")[..16];

    public IReadOnlyList<JsonObject> History()
    {
        var list = new List<JsonObject>();
        if (!File.Exists(FilePath)) return list;
        try
        {
            foreach (var line in File.ReadLines(FilePath, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try { if (JsonNode.Parse(line) is JsonObject o) list.Add(o); } catch (JsonException) { }
            }
        }
        catch (IOException) { }
        return list;
    }

    public JsonObject? Current() => History().LastOrDefault();

    /// <summary>
    /// Appends a new version if the text actually changed. Idempotent by content hash: this is called on every
    /// request, so re-appending an unchanged value would turn the history into a request log.
    /// </summary>
    public JsonObject? Record(string? text, string author = "")
    {
        text = (text ?? "").Trim();
        if (text.Length == 0) return null;
        var digest = Digest(text);
        lock (ProcessLock)
        {
            var latest = Current();
            if (latest is not null && latest["hash"]?.GetValue<string>() == digest) return latest;
            var now = DateTimeOffset.UtcNow;
            var entry = new JsonObject
            {
                ["version"] = (latest?["version"]?.GetValue<int>() ?? 0) + 1,
                ["hash"] = digest,
                ["ts_utc"] = now.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["ts"] = now.ToUnixTimeMilliseconds() / 1000.0,
                ["author"] = author,
                ["text"] = text,
            };
            try
            {
                System.IO.Directory.CreateDirectory(Directory);
                File.AppendAllText(FilePath, entry.ToJsonString(new JsonSerializerOptions
                {
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                }) + "\n", Encoding.UTF8);
            }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            return entry;
        }
    }

    /// <summary>Shape the technical file embeds (Annex IV system-prompt registry).</summary>
    public JsonObject Summary()
    {
        var versions = History();
        var current = versions.LastOrDefault();
        var history = new JsonArray();
        foreach (var v in versions)
        {
            var o = new JsonObject();
            foreach (var kv in v.Where(k => k.Key != "ts")) o[kv.Key] = kv.Value?.DeepClone();
            history.Add(o);
        }
        return new JsonObject
        {
            ["configured"] = current is not null,
            ["current_version"] = current?["version"]?.DeepClone(),
            ["current_hash"] = current?["hash"]?.DeepClone(),
            ["current_text"] = current?["text"]?.DeepClone() ?? "",
            ["changed_at"] = current?["ts_utc"]?.DeepClone(),
            ["version_count"] = versions.Count,
            ["history"] = history,
        };
    }
}
