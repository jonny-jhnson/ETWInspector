using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace EtwInspector.Provider.Enumeration
{
    /// <summary>
    /// Enumerates TraceLogging providers across a list of binaries. TraceLogging
    /// metadata is embedded inside DLLs/EXEs/SYS files at compile time, so the
    /// only way to discover it is to scan binaries for the "ETW0" signature and
    /// parse what follows.
    ///
    /// The same TraceLogging provider (same name -> same GUID) can be embedded
    /// in multiple binaries. We merge those into a single ProviderSnapshot per
    /// GUID, with a Sources list of every file the provider was found in, and
    /// events deduplicated within the entry by (EventName, fields signature).
    /// </summary>
    internal static class TraceLoggingEnumerator
    {
        private static readonly byte[] Etw0Signature = new byte[] { 0x45, 0x54, 0x57, 0x30 };

        public static List<ProviderSnapshot> Scan(IEnumerable<string> files, Action<string> verbose = null)
        {
            // GUID -> aggregated provider record being built up across files
            var byGuid = new Dictionary<string, AggregatedProvider>(StringComparer.OrdinalIgnoreCase);
            int hitCount = 0;
            int scanned = 0;

            foreach (var file in files)
            {
                scanned++;
                if (!HasEtw0Signature(file)) continue;
                hitCount++;

                TraceLoggingSchema schema;
                try
                {
                    schema = TraceLoggingUtilities.ParseTraceLoggingMetadata(file);
                }
                catch (Exception ex)
                {
                    verbose?.Invoke($"Skip {file}: parse failed ({ex.Message})");
                    continue;
                }
                if (schema == null) continue;

                // The parser returns providers and events at the schema level
                // without an explicit linkage. Each TraceLogging binary contains
                // a small number of providers (often one) and we treat all of
                // its events as belonging to all of its providers, which matches
                // how TraceLogging is laid out in practice (a binary registers
                // its providers and emits events under them).
                if (schema.Providers == null || schema.Providers.Count == 0) continue;

                foreach (var provider in schema.Providers)
                {
                    if (string.IsNullOrEmpty(provider.ProviderName)) continue;

                    var guid = NormalizeGuid(provider.ProviderGUID);
                    if (string.IsNullOrEmpty(guid))
                    {
                        // Some early TraceLogging blob types (TlgBlobProvider v1)
                        // don't carry the GUID directly. We can't reliably merge
                        // those, so skip rather than over-attribute.
                        continue;
                    }

                    if (!byGuid.TryGetValue(guid, out var agg))
                    {
                        agg = new AggregatedProvider
                        {
                            ProviderGuid = guid,
                            ProviderName = provider.ProviderName,
                        };
                        byGuid[guid] = agg;
                    }
                    agg.Sources.Add(file);

                    // Attribute every event in this binary to this provider.
                    if (schema.Events != null)
                    {
                        foreach (var e in schema.Events)
                        {
                            var key = EventDedupKey(e);
                            if (agg.SeenEventKeys.Add(key))
                            {
                                agg.Events.Add(ToEventSnapshot(e));
                            }
                        }
                    }
                }
            }

            verbose?.Invoke($"TraceLogging scan: {scanned} files probed, {hitCount} carried ETW0, {byGuid.Count} unique providers found.");

            return byGuid.Values
                .OrderBy(a => a.ProviderName, StringComparer.OrdinalIgnoreCase)
                .Select(a => a.ToProviderSnapshot())
                .ToList();
        }

        // Stream the file looking for the literal ASCII "ETW0" byte sequence.
        // Only reads the first portion of the file so non-TraceLogging files
        // pay near-zero cost.
        private static bool HasEtw0Signature(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan))
                {
                    var buf = new byte[64 * 1024];
                    int carry = 0;
                    long total = 0;
                    const long MaxScan = 16L * 1024 * 1024; // 16 MB is plenty; .text section is usually well within
                    while (total < MaxScan)
                    {
                        int read = fs.Read(buf, carry, buf.Length - carry);
                        if (read <= 0) break;
                        int searchEnd = carry + read;
                        for (int i = 0; i <= searchEnd - 4; i++)
                        {
                            if (buf[i] == Etw0Signature[0]
                                && buf[i + 1] == Etw0Signature[1]
                                && buf[i + 2] == Etw0Signature[2]
                                && buf[i + 3] == Etw0Signature[3])
                            {
                                return true;
                            }
                        }
                        // Carry over the last 3 bytes in case the signature spans the chunk boundary
                        carry = Math.Min(3, searchEnd);
                        Array.Copy(buf, searchEnd - carry, buf, 0, carry);
                        total += read;
                    }
                }
            }
            catch
            {
                // Locked files, access denied, etc. -> just skip
            }
            return false;
        }

        private static EventSnapshot ToEventSnapshot(TraceLoggingEventMetadata e)
        {
            return new EventSnapshot
            {
                Id = 0,                       // TraceLogging events have no stable numeric ID
                Version = 0,
                Level = e.Level,
                Opcode = e.Opcode,
                Task = 0,
                Keywords = ParseHexKeywords(e.KeywordHex),
                KeywordNames = string.IsNullOrEmpty(e.KeywordName)
                    ? new List<string>()
                    : new List<string> { e.KeywordName },
                Description = e.EventName,
                Template = BuildTemplateXml(e.Fields),
            };
        }

        private static long ParseHexKeywords(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return 0;
            var s = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex.Substring(2) : hex;
            return long.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : 0;
        }

        // Manifest-style template XML so the existing diff/UI rendering works
        // uniformly for TraceLogging events.
        private static string BuildTemplateXml(IList<FieldMetadata> fields)
        {
            if (fields == null || fields.Count == 0) return null;
            var sb = new StringBuilder();
            sb.Append("<template>");
            foreach (var f in fields)
            {
                sb.Append("<data name=\"").Append(XmlEscape(f.FieldName ?? string.Empty)).Append("\"");
                sb.Append(" inType=\"").Append(XmlEscape(f.InType ?? string.Empty)).Append("\"");
                if (!string.IsNullOrEmpty(f.OutType))
                {
                    sb.Append(" outType=\"").Append(XmlEscape(f.OutType)).Append("\"");
                }
                sb.Append("/>");
            }
            sb.Append("</template>");
            return sb.ToString();
        }

        // Identity for dedup within one provider's event list. Two events with
        // the same name and the same field schema are the same event regardless
        // of which binary it came from.
        private static string EventDedupKey(TraceLoggingEventMetadata e)
        {
            var sb = new StringBuilder();
            sb.Append(e.EventName ?? string.Empty);
            sb.Append('|').Append(e.Level).Append('|').Append(e.Opcode);
            sb.Append('|').Append(e.KeywordHex ?? string.Empty);
            if (e.Fields != null)
            {
                foreach (var f in e.Fields)
                {
                    sb.Append('#').Append(f.FieldName ?? string.Empty)
                      .Append(':').Append(f.InType ?? string.Empty);
                }
            }
            return sb.ToString();
        }

        private static string NormalizeGuid(string guid)
        {
            if (string.IsNullOrEmpty(guid)) return string.Empty;
            return guid.Trim().Trim('{', '}').ToLowerInvariant();
        }

        private static string XmlEscape(string s)
        {
            if (s == null) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        private class AggregatedProvider
        {
            public string ProviderGuid { get; set; }
            public string ProviderName { get; set; }
            public SortedSet<string> Sources { get; set; } = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> SeenEventKeys { get; set; } = new HashSet<string>(StringComparer.Ordinal);
            public List<EventSnapshot> Events { get; set; } = new List<EventSnapshot>();

            public ProviderSnapshot ToProviderSnapshot()
            {
                return new ProviderSnapshot
                {
                    ProviderGuid = ProviderGuid,
                    ProviderName = ProviderName,
                    SchemaSource = "TraceLogging",
                    ResourceFilePath = null,
                    Sources = Sources.ToList(),
                    Events = Events
                        .OrderBy(e => e.Description, StringComparer.OrdinalIgnoreCase)
                        .ToList(),
                };
            }
        }
    }
}
