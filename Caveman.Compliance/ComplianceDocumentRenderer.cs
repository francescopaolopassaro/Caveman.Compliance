// ------------------------------------------------------------------------------
// Caveman.Compliance
// Copyright (c) 2026 Passaro Francesco Paolo
// Licensed under the MIT License. See LICENSE file in the project root.
//
// Renders a compliance document (the JsonObject built by ComplianceDocuments) to PDF. The layout is
// HTML + CSS turned into PDF by Stilo.Documents - the same engine the rest of the Caveman family uses -
// so the package ships no PDF writer of its own and the PDF can be produced anywhere .NET runs.
// ------------------------------------------------------------------------------
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using Stilo.Documents.Converters;
using Stilo.Documents.HtmlRenderer.Layout;

namespace Caveman.Compliance;

public static class ComplianceDocumentRenderer
{
    private const string Style = """
        body { font-family: Helvetica; font-size: 9pt; color: #1f2933; line-height: 1.35; }
        h1 { font-size: 20pt; color: #17324d; margin-top: 4px; margin-bottom: 2px; }
        h2 { font-size: 12.5pt; color: #17324d; border-bottom: 1.5px solid #17324d; padding-bottom: 2px; margin-top: 16px; margin-bottom: 6px; }
        h3 { font-size: 10pt; color: #3e5c76; margin-top: 10px; margin-bottom: 3px; }
        p { margin-top: 3px; margin-bottom: 3px; }
        .muted { color: #6b7785; font-size: 8pt; }
        .banner { background: #17324d; color: #ffffff; padding: 10px 12px; margin-bottom: 8px; }
        .banner table.kv td { border: none; padding: 0 4px; }
        .banner .title { font-size: 17pt; color: #ffffff; margin: 0; }
        .banner .sub { font-size: 8.5pt; color: #cfdcea; margin: 2px 0 0 0; }
        .note { background: #fff8e1; border: 1px solid #f0c36d; padding: 6px 8px; margin: 6px 0; font-size: 8pt; color: #5c4400; }
        .alert { background: #fdecea; border: 1px solid #e57373; padding: 6px 8px; margin: 6px 0; font-size: 8.5pt; color: #7a1c1c; }
        table { border-collapse: collapse; width: 100%; margin-top: 3px; margin-bottom: 6px; }
        th { background: #17324d; color: #ffffff; text-align: left; padding: 4px 5px; border: 1px solid #17324d; font-size: 8pt; }
        td { padding: 3.5px 5px; border: 1px solid #d3dae1; vertical-align: top; font-size: 8pt; }
        tr.alt td { background: #f3f6f9; }
        table.kv td { border: none; border-bottom: 1px solid #e6ebf0; padding: 3px 5px; font-size: 8.5pt; }
        table.kv td.k { color: #52606d; font-weight: bold; width: 28%; }
        .badge { padding: 1px 5px; color: #ffffff; font-size: 7.5pt; font-weight: bold; }
        .high { background: #c62828; } .medium { background: #ef8a17; } .low { background: #2e7d32; }
        .yes { background: #2e7d32; } .no { background: #c62828; } .neutral { background: #607d8b; }
        .bar { background: #2f6f9f; height: 9px; }
        .bar-high { background: #c62828; } .bar-medium { background: #ef8a17; } .bar-low { background: #2e7d32; }
        .item { margin: 2px 0 2px 10px; }
        .stat { font-size: 15pt; color: #17324d; font-weight: bold; }
        """;

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private static string Label(string key)
    {
        var s = key.Replace('_', ' ');
        return s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
    }

    private static string Text(JsonNode? n) => n switch
    {
        null => "",
        JsonValue v => v.TryGetValue<string>(out var s) ? s : v.ToJsonString().Trim('"'),
        JsonArray a => string.Join(", ", a.Select(Text)),
        JsonObject o => string.Join(", ", o.Select(kv => $"{kv.Key}: {Text(kv.Value)}")),
        _ => n.ToJsonString(),
    };

    private static string Logo()
    {
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("Caveman.Compliance.caveman-icon.png");
            if (s is null) return "";
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return $"<img src='data:image/png;base64,{Convert.ToBase64String(ms.ToArray())}' width='38' height='38'/>";
        }
        catch { return ""; }
    }

    // ── building blocks ──────────────────────────────────────────────────

    private static string Badge(string text, string cls) => $"<span class='badge {cls}'>{E(text)}</span>";
    private static string Risk(string level) => Badge(level, level is "high" or "medium" or "low" ? level : "neutral");
    private static string YesNo(bool v, string no = "NO") => v ? Badge("yes", "yes") : Badge(no, "no");

    private static void Table(StringBuilder sb, string[] headers, IEnumerable<string[]> rows, double[] widths)
    {
        sb.Append("<table><thead><tr>");
        for (var i = 0; i < headers.Length; i++)
            sb.Append($"<th style='width:{widths[i].ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)}%'>{E(headers[i])}</th>");
        sb.Append("</tr></thead><tbody>");
        var alt = false;
        foreach (var r in rows)
        {
            sb.Append(alt ? "<tr class='alt'>" : "<tr>");
            foreach (var c in r) sb.Append("<td>").Append(c).Append("</td>");   // cells arrive already encoded / badge markup
            sb.Append("</tr>");
            alt = !alt;
        }
        sb.Append("</tbody></table>");
    }

    private static void KeyValues(StringBuilder sb, IEnumerable<(string k, string v)> pairs)
    {
        sb.Append("<table class='kv'>");
        foreach (var (k, v) in pairs) sb.Append($"<tr><td class='k'>{E(k)}</td><td>{E(v)}</td></tr>");
        sb.Append("</table>");
    }

    private static void Bullets(StringBuilder sb, IEnumerable<string> items)
    {
        foreach (var i in items) sb.Append($"<div class='item'>&#8226;&nbsp; {E(i)}</div>");
    }

    private static void BarChart(StringBuilder sb, JsonObject counts, string cls = "bar")
    {
        var items = counts.Select(kv => (kv.Key, Value: kv.Value?.GetValue<int>() ?? 0)).OrderByDescending(x => x.Value).ToList();
        if (items.Count == 0) return;
        var max = Math.Max(1, items.Max(x => x.Value));
        sb.Append("<table class='kv'>");
        foreach (var (k, v) in items)
        {
            var pct = Math.Max(2, (int)Math.Round(v * 100.0 / max));
            var c = cls == "bar" && k is "high" or "medium" or "low" ? "bar-" + k : cls;
            sb.Append($"<tr><td style='width:24%'>{E(k)}</td><td style='width:66%'><div class='bar {c}' style='width:{pct}%'></div></td><td style='width:10%'>{v:N0}</td></tr>");
        }
        sb.Append("</table>");
    }

    private static void RulesTable(StringBuilder sb, JsonArray rules) => Table(sb,
        new[] { "Rule", "Category", "Risk", "Action", "Scope", "On" },
        rules.OfType<JsonObject>().Select(r => new[]
        {
            $"<b>{E(Text(r["id"]))}</b>", E(Text(r["category"])), Risk(Text(r["risk_level"])), E(Text(r["action"])), E(Text(r["scope"])),
            YesNo(r["enabled"]?.GetValue<bool>() ?? false),
        }),
        new[] { 30.0, 16, 12, 14, 14, 14 });

    private static void MatrixTable(StringBuilder sb, JsonArray rows) => Table(sb,
        new[] { "Module", "Framework", "Article", "Obligation" },
        rows.OfType<JsonObject>().Select(r => new[] { E(Text(r["module"])), E(Text(r["framework"])), E(Text(r["article"])), E(Text(r["obligation"])) }),
        new[] { 22.0, 20, 13, 45 });

    /// <summary>
    /// Renders a section whose values may be scalars, lists or lists of rules. Structures are split out into
    /// their own readable block instead of being stringified into one cell.
    /// </summary>
    private static void Section(StringBuilder sb, JsonObject section)
    {
        var scalars = new List<(string, string)>();
        void FlushScalars() { if (scalars.Count > 0) { KeyValues(sb, scalars); scalars = new(); } }

        foreach (var (key, value) in section)
        {
            var label = Label(key);
            if (value is JsonArray arr && arr.Count > 0 && arr[0] is JsonObject first)
            {
                FlushScalars();
                sb.Append($"<h3>{E(label)}</h3>");
                if (first.ContainsKey("id") && first.ContainsKey("risk_level") && first.ContainsKey("action")) RulesTable(sb, arr);
                else foreach (var item in arr.OfType<JsonObject>())
                        sb.Append($"<div class='item'>&#8226;&nbsp; {E(string.Join("; ", item.Select(kv => $"{kv.Key}: {Text(kv.Value)}")))}</div>");
            }
            else if (value is JsonArray list) scalars.Add((label, list.Count == 0 ? "-" : string.Join(", ", list.Select(Text))));
            else if (value is JsonObject obj) scalars.Add((label, obj.Count == 0 ? "-" : Text(obj)));
            else scalars.Add((label, Text(value)));
        }
        FlushScalars();
    }

    // ── document ─────────────────────────────────────────────────────────

    /// <summary>Renders the document as a self-contained HTML page (the input of the PDF conversion).</summary>
    public static string ToHtml(JsonObject doc)
    {
        var sb = new StringBuilder();
        var section = 0;
        string Num(string title) => $"{++section}. {title}";
        sb.Append("<html><head><meta charset='utf-8'/><title>").Append(E(Text(doc["document"]))).Append("</title><style>").Append(Style).Append("</style></head><body>");

        sb.Append("<div class='banner'><table class='kv'><tr><td style='width:6%'>").Append(Logo()).Append("</td><td>")
          .Append($"<p class='title'>{E(Text(doc["document"]))}</p><p class='sub'>Generated {E(Text(doc["generated_at"]))} &#183; Caveman Compliance Engine</p>")
          .Append("</td></tr></table></div>");

        if (doc["disclaimer"] is { } disc) sb.Append($"<div class='note'>{E(Text(disc))}</div>");

        if (doc["system"] is JsonObject system)
        {
            sb.Append($"<h2>{E(Num("System"))}</h2>");
            KeyValues(sb, system.Select(kv => (Label(kv.Key), Text(kv.Value))));
        }

        if (doc["engine"] is JsonObject engine)
        {
            sb.Append($"<h2>{E(Num("Engine configuration"))}</h2>");
            KeyValues(sb, new[]
            {
                ("Status", Text(engine["status"])),
                ("Fallback", Text(engine["fallback"])),
                ("Rules enabled", $"{Text(engine["rules_enabled"])} of {Text(engine["rules_total"])}"),
            }.Concat(engine["agent_profile"] is null ? Array.Empty<(string, string)>() : new[] { ("Agent profile", Text(engine["agent_profile"])) }));
        }

        if (doc["guardrails"] is JsonArray guardrails && guardrails.Count > 0)
        {
            sb.Append($"<h2>{E(Num("Active guardrails"))}</h2>");
            RulesTable(sb, guardrails);
        }

        if (doc["traceability_matrix"] is JsonArray matrix && matrix.Count > 0)
        {
            sb.Append($"<h2>{E(Num("Traceability: control to legal obligation"))}</h2>");
            MatrixTable(sb, matrix);
        }

        if (doc["system_prompt_registry"] is JsonObject reg)
        {
            sb.Append("<h2>System instruction registry</h2>");
            if (!(reg["configured"]?.GetValue<bool>() ?? false))
                sb.Append("<p class='muted'>No organisation-level system instructions are configured; requests reach the model with only the caller's own prompt.</p>");
            else
            {
                KeyValues(sb, new[]
                {
                    ("Current version", Text(reg["current_version"])), ("Content hash", Text(reg["current_hash"])),
                    ("In force since", Text(reg["changed_at"])), ("Versions recorded", Text(reg["version_count"])),
                });
                sb.Append("<p class='muted'>Text in force:</p>").Append($"<div class='note'>{E(Text(reg["current_text"]))}</div>");
                if (reg["history"] is JsonArray hist && hist.Count > 1)
                {
                    sb.Append("<h3>Version history</h3>");
                    Table(sb, new[] { "Version", "Changed at", "Hash", "Author" },
                        hist.OfType<JsonObject>().Select(h => new[]
                        {
                            E(Text(h["version"])), E(Text(h["ts_utc"])), E(Text(h["hash"])), E(string.IsNullOrEmpty(Text(h["author"])) ? "-" : Text(h["author"])),
                        }), new[] { 14.0, 34, 32, 20 });
                }
            }
        }

        if (doc["record_keeping"] is JsonObject rk)
        {
            sb.Append($"<h2>{E(Num("Record keeping (Art. 12)"))}</h2>");
            KeyValues(sb, rk.Select(kv => (Label(kv.Key), Text(kv.Value))));
        }

        if (doc["human_oversight"] is JsonObject ho)
        {
            sb.Append($"<h2>{E(Num("Human oversight (Art. 14)"))}</h2>");
            if (ho["mechanisms"] is JsonArray m) Bullets(sb, m.Select(Text));
        }

        foreach (var (key, title) in new[]
        {
            ("processing_description", "Processing description"), ("measures", "Technical and organisational measures"),
            ("necessity_and_proportionality", "Necessity and proportionality"), ("deployment_context", "Deployment context"),
        })
        {
            if (doc[key] is not JsonObject s) continue;
            sb.Append($"<h2>{E(title)}</h2>");
            Section(sb, s);
        }

        if (doc["risks"] is JsonObject risks)
        {
            sb.Append("<h2>Risks</h2>");
            if (risks["identified"] is JsonArray ident) Bullets(sb, ident.Select(Text));
            sb.Append("<h3>Mitigations</h3>");
            if (risks["mitigations"] is JsonArray mit) Bullets(sb, mit.Select(Text));
            KeyValues(sb, new[] { ("Residual risk", Text(risks["residual_risk_acceptance"])) });
        }

        if (doc["oversight_measures"] is JsonArray om && om.Count > 0)
        {
            sb.Append("<h2>Human oversight measures</h2>");
            Bullets(sb, om.Select(Text));
        }

        if (doc["rights_assessment"] is JsonArray rights)
        {
            sb.Append("<h2>Fundamental rights assessment</h2>");
            Table(sb, new[] { "Right", "Impact", "Controls" },
                rights.OfType<JsonObject>().Select(r => new[]
                {
                    E(Text(r["right"])), E(Text(r["impact"])), E(r["controls"] is JsonArray c && c.Count > 0 ? string.Join(", ", c.Select(Text)) : "-"),
                }), new[] { 26.0, 44, 30 });
        }

        if (doc["statistics"] is JsonObject stats) Statistics(sb, stats);

        if (doc["audit_chain"] is JsonObject chain)
        {
            sb.Append("<h2>Audit trail integrity</h2>");
            var valid = chain["valid"]?.GetValue<bool>() ?? false;
            KeyValues(sb, new[]
            {
                ("Entries", Text(chain["entries"])), ("Chain valid", valid ? "yes" : "NO - see note"),
                ("Note", string.IsNullOrEmpty(Text(chain["reason"])) ? "No tampering detected." : Text(chain["reason"])),
            });
            if (!valid) sb.Append("<div class='alert'>The audit chain does not verify: at least one entry was edited, removed or reordered after it was written.</div>");
        }

        if (doc["backend_health"] is JsonArray health && health.Count > 0)
        {
            sb.Append("<h2>Control implementation status</h2>");
            sb.Append("<p class='muted'>Whether each control is enabled in the policy and whether the guard that implements it is actually operational.</p>");
            Table(sb, new[] { "Control", "Backend", "Enabled", "Operational" },
                health.OfType<JsonObject>().Select(h => new[]
                {
                    $"<b>{E(Text(h["rule_id"]))}</b>", E(Text(h["backend"])), YesNo(h["rule_enabled"]?.GetValue<bool>() ?? false, "no"),
                    OperationalBadge(h),
                }), new[] { 32.0, 26, 18, 24 });
        }

        if (doc["ineffective_controls"] is JsonArray bad && bad.Count > 0)
        {
            sb.Append("<h2>Controls enabled but not operational</h2>");
            sb.Append("<div class='alert'>These rules are switched on in the compliance policy, but the guard that implements them is disabled or unavailable - they currently inspect nothing.</div>");
            Table(sb, new[] { "Rule", "Backend", "State", "Reason" },
                bad.OfType<JsonObject>().Select(h => new[] { E(Text(h["rule_id"])), E(Text(h["backend"])), E(Text(h["backend_state"])), E(Text(h["note"])) }),
                new[] { 26.0, 22, 16, 36 });
        }

        if (doc["coverage_gaps"] is JsonArray gaps && gaps.Count > 0)
        {
            sb.Append("<h2>Uncovered obligations (disabled controls)</h2>");
            sb.Append("<p class='muted'>These obligations have no active control in the current configuration.</p>");
            MatrixTable(sb, gaps);
        }

        if (doc["open_items"] is JsonArray open && open.Count > 0)
        {
            sb.Append("<h2>Open items requiring human completion</h2>");
            foreach (var i in open) sb.Append($"<div class='item'>&#9744;&nbsp; {E(Text(i))}</div>");
        }

        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static string OperationalBadge(JsonObject h)
    {
        if (h["effective"]?.GetValue<bool>() ?? false) return Badge("yes", "yes");
        var state = Text(h["backend_state"]);
        // a rule switched off in the policy is not a failing guard: say so instead of a red "operational"
        return state == "operational" ? Badge("rule off", "neutral") : Badge(state, "no");
    }

    private static void Statistics(StringBuilder sb, JsonObject stats)
    {
        sb.Append("<h2>Operational statistics</h2>");
        var lat = stats["latency_ms"] as JsonObject;
        sb.Append("<table class='kv'><tr>")
          .Append($"<td><span class='stat'>{(stats["total_calls"]?.GetValue<int>() ?? 0):N0}</span><br/><span class='muted'>transactions processed</span></td>")
          .Append($"<td><span class='stat'>{(stats["calls_with_findings"]?.GetValue<int>() ?? 0):N0}</span><br/><span class='muted'>with findings</span></td>")
          .Append($"<td><span class='stat'>{Text(stats["violation_rate_pct"])}%</span><br/><span class='muted'>violation rate</span></td>")
          .Append($"<td><span class='stat'>{Text(lat?["avg"])}</span><br/><span class='muted'>avg ms (p95 {Text(lat?["p95"])} &#183; max {Text(lat?["max"])})</span></td>")
          .Append("</tr></table>");

        if (stats["by_category"] is JsonObject cats && cats.Count > 0) { sb.Append("<h3>Findings by category</h3>"); BarChart(sb, cats); }
        if (stats["by_risk_level"] is JsonObject risk && risk.Count > 0) { sb.Append("<h3>Findings by risk level</h3>"); BarChart(sb, risk); }
    }

    // ── output ───────────────────────────────────────────────────────────

    /// <summary>Renders the document to a PDF stream (A4, 36 pt margins).</summary>
    public static async Task<Stream> ToPdfAsync(JsonObject doc, CancellationToken ct = default)
    {
        var converter = new HtmlToPdfConverter(PageLayout.A4Portrait(40));
        return await converter.ConvertAsync(ToHtml(doc), ct).ConfigureAwait(false);
    }

    /// <summary>Renders the document and writes the PDF to <paramref name="path"/>.</summary>
    public static async Task<string> SavePdfAsync(JsonObject doc, string path, CancellationToken ct = default)
    {
        await using var pdf = await ToPdfAsync(doc, ct).ConfigureAwait(false);
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        await using var file = File.Create(path);
        await pdf.CopyToAsync(file, ct).ConfigureAwait(false);
        return path;
    }

    /// <summary>Writes the JSON form of the document (the source of truth the PDF renders).</summary>
    public static async Task<string> SaveJsonAsync(JsonObject doc, string path, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(path, doc.ToJsonString(new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        }), Encoding.UTF8, ct).ConfigureAwait(false);
        return path;
    }
}
