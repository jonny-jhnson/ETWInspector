using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management.Automation;

namespace EtwInspector.Provider.Enumeration
{
    public class EtwSnapshot
    {
        public string SchemaVersion { get; set; } = "1.1";
        public string OSVersion { get; set; }
        public List<ProviderSnapshot> Providers { get; set; } = new List<ProviderSnapshot>();
    }

    public class ProviderSnapshot
    {
        public string ProviderGuid { get; set; }
        public string ProviderName { get; set; }
        public string SchemaSource { get; set; }
        public string ResourceFilePath { get; set; }
        // Populated only for TraceLogging providers, which can be embedded in
        // multiple binaries. Sorted, deduplicated paths. Manifest/MOF use the
        // single ResourceFilePath above and leave this null.
        public List<string> Sources { get; set; }
        public List<KeywordSnapshot> Keywords { get; set; } = new List<KeywordSnapshot>();
        public List<EventSnapshot> Events { get; set; } = new List<EventSnapshot>();
    }

    public class KeywordSnapshot
    {
        public string Name { get; set; }
        public long Value { get; set; }
    }

    public class EventSnapshot
    {
        public int Id { get; set; }
        public byte Version { get; set; }
        public byte Level { get; set; }
        public byte Opcode { get; set; }
        public int Task { get; set; }
        public long Keywords { get; set; }
        public List<string> KeywordNames { get; set; } = new List<string>();
        public string Description { get; set; }
        public string Template { get; set; }
    }

    public class SnapshotDiff
    {
        public string OSVersionA { get; set; }
        public string OSVersionB { get; set; }
        public List<ProviderSnapshot> ProvidersAdded { get; set; } = new List<ProviderSnapshot>();
        public List<ProviderSnapshot> ProvidersRemoved { get; set; } = new List<ProviderSnapshot>();
        public List<ProviderDiff> ProvidersChanged { get; set; } = new List<ProviderDiff>();
    }

    public class ProviderDiff
    {
        public string ProviderGuid { get; set; }
        public string ProviderName { get; set; }
        public List<FieldChange> ProviderFieldsChanged { get; set; } = new List<FieldChange>();
        public List<EventSnapshot> EventsAdded { get; set; } = new List<EventSnapshot>();
        public List<EventSnapshot> EventsRemoved { get; set; } = new List<EventSnapshot>();
        public List<EventDiff> EventsChanged { get; set; } = new List<EventDiff>();
    }

    public class EventDiff
    {
        public int Id { get; set; }
        public byte Version { get; set; }
        public List<FieldChange> Changes { get; set; } = new List<FieldChange>();
    }

    public class FieldChange
    {
        public string Field { get; set; }
        public object A { get; set; }
        public object B { get; set; }
    }

    internal static class SnapshotIO
    {
        private static readonly JsonSerializerSettings IndentedSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Ignore
        };

        private static readonly JsonSerializerSettings CompactSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.None,
            NullValueHandling = NullValueHandling.Ignore
        };

        public static bool IsNdjsonPath(string path)
        {
            var ext = Path.GetExtension(path);
            return string.Equals(ext, ".ndjson", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(ext, ".jsonl", StringComparison.OrdinalIgnoreCase);
        }

        public static void WriteJson(EtwSnapshot snapshot, string path)
        {
            string json = JsonConvert.SerializeObject(snapshot, IndentedSettings);
            File.WriteAllText(path, json);
        }

        public static void WriteNdjson(EtwSnapshot snapshot, string path)
        {
            using (var writer = new StreamWriter(path, false, new System.Text.UTF8Encoding(false)))
            {
                var header = new SnapshotHeader
                {
                    SchemaVersion = snapshot.SchemaVersion,
                    OSVersion = snapshot.OSVersion
                };
                writer.WriteLine(JsonConvert.SerializeObject(header, CompactSettings));
                foreach (var p in snapshot.Providers)
                {
                    writer.WriteLine(JsonConvert.SerializeObject(p, CompactSettings));
                }
            }
        }

        public static EtwSnapshot Read(string path)
        {
            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException($"Snapshot file not found: {fullPath}");
            }

            EtwSnapshot snap = IsNdjsonPath(fullPath) ? ReadNdjson(fullPath) : ReadJson(fullPath);

            if (snap == null)
            {
                throw new InvalidDataException($"Could not parse snapshot file: {fullPath}");
            }
            if (snap.Providers == null)
            {
                snap.Providers = new List<ProviderSnapshot>();
            }
            return snap;
        }

        private static EtwSnapshot ReadJson(string path)
        {
            string json = File.ReadAllText(path);
            return JsonConvert.DeserializeObject<EtwSnapshot>(json);
        }

        private static EtwSnapshot ReadNdjson(string path)
        {
            var snap = new EtwSnapshot();
            bool first = true;
            foreach (var rawLine in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(rawLine)) continue;
                if (first)
                {
                    var header = JsonConvert.DeserializeObject<SnapshotHeader>(rawLine);
                    if (header != null)
                    {
                        snap.SchemaVersion = header.SchemaVersion ?? snap.SchemaVersion;
                        snap.OSVersion = header.OSVersion;
                    }
                    first = false;
                    continue;
                }
                var p = JsonConvert.DeserializeObject<ProviderSnapshot>(rawLine);
                if (p != null) snap.Providers.Add(p);
            }
            return snap;
        }
    }

    internal class SnapshotHeader
    {
        public string SchemaVersion { get; set; }
        public string OSVersion { get; set; }
    }

    internal static class SnapshotBuilder
    {
        public static ProviderSnapshot ToSnapshot(_PROVIDER_METADATA p)
        {
            var snap = new ProviderSnapshot
            {
                ProviderGuid = p.providerGuid,
                ProviderName = p.providerName,
                SchemaSource = p.schemaSource,
                ResourceFilePath = p.resourceFilePath
            };

            if (p.eventKeywords != null)
            {
                foreach (var k in p.eventKeywords)
                {
                    snap.Keywords.Add(new KeywordSnapshot
                    {
                        Name = k.Name,
                        Value = k.Value
                    });
                }
            }
            snap.Keywords = snap.Keywords
                .OrderBy(k => k.Value)
                .ThenBy(k => k.Name, StringComparer.Ordinal)
                .ToList();

            if (p.eventMetadata != null)
            {
                foreach (var e in p.eventMetadata)
                {
                    var es = new EventSnapshot
                    {
                        Id = (int)e.Id,
                        Version = e.Version,
                        Level = e.Level != null ? (byte)e.Level.Value : (byte)0,
                        Opcode = e.Opcode != null ? (byte)e.Opcode.Value : (byte)0,
                        Task = e.Task != null ? e.Task.Value : 0,
                        Description = e.Description,
                        Template = e.Template
                    };

                    long kwBitmap = 0;
                    if (e.Keywords != null)
                    {
                        foreach (var k in e.Keywords)
                        {
                            if (!string.IsNullOrEmpty(k.Name))
                            {
                                es.KeywordNames.Add(k.Name);
                            }
                            kwBitmap |= k.Value;
                        }
                    }
                    es.Keywords = kwBitmap;
                    es.KeywordNames = es.KeywordNames
                        .OrderBy(s => s, StringComparer.Ordinal)
                        .ToList();

                    snap.Events.Add(es);
                }
            }
            snap.Events = snap.Events
                .OrderBy(e => e.Id)
                .ThenBy(e => e.Version)
                .ToList();

            return snap;
        }
    }

    /// <summary>
    /// <para type="synopsis">Export-EtwSnapshot serializes Manifest, MOF, and TraceLogging provider metadata to a JSON or NDJSON file.</para>
    /// <para type="description">Export-EtwSnapshot enumerates ETW providers on the local machine and writes them, with their events and keywords, to a snapshot file. By default it covers all three schema sources: registered Manifest providers, MOF providers (via the WMI repository), and TraceLogging providers (by scanning binaries under C:\Windows\System32 and C:\Windows\System32\drivers for the embedded ETW0 metadata). Use -SkipTraceLogging for a fast Manifest+MOF-only export, or -ScanPath to add directories to the TraceLogging scan.</para>
    /// <para type="description">Output format is chosen by file extension: .ndjson or .jsonl produces newline-delimited JSON (one provider per line, with a header on the first line) which diffs cleanly and streams well; any other extension produces pretty-printed JSON. Run this on two machines (or before/after an update) and feed the resulting files to Compare-EtwSnapshot to see what changed.</para>
    /// </summary>
    /// <example>
    /// <para> PS C:\> Export-EtwSnapshot C:\snapshots\baseline.ndjson</para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Export-EtwSnapshot C:\snapshots\fast.ndjson -SkipTraceLogging</para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Export-EtwSnapshot C:\snapshots\full.ndjson -ScanPath 'C:\Program Files\MyApp'</para>
    /// </example>
    [Cmdlet(VerbsData.Export, "EtwSnapshot")]
    public class ExportEtwSnapshotCommand : Cmdlet
    {
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string OutputPath { get; set; }

        [Parameter(Mandatory = false)]
        public SwitchParameter SkipTraceLogging { get; set; }

        [Parameter(Mandatory = false)]
        public string[] ScanPath { get; set; }

        protected override void ProcessRecord()
        {
            try
            {
                var enumerator = new GetEtwProvidersCommand();
                var providers = enumerator.ProcessStandardProviders("All");

                var snapshot = new EtwSnapshot
                {
                    OSVersion = GetOSVersionString()
                };

                foreach (var p in providers)
                {
                    snapshot.Providers.Add(SnapshotBuilder.ToSnapshot(p));
                }

                if (!SkipTraceLogging)
                {
                    var scanRoots = new List<string>
                    {
                        @"C:\Windows\System32",
                        @"C:\Windows\System32\drivers",
                    };
                    if (ScanPath != null) scanRoots.AddRange(ScanPath);

                    var files = new List<string>();
                    foreach (var root in scanRoots)
                    {
                        files.AddRange(SafeEnumerateBinaries(root));
                    }
                    WriteVerbose($"TraceLogging: scanning {files.Count} files...");
                    var tlgProviders = TraceLoggingEnumerator.Scan(files, msg => WriteVerbose(msg));
                    snapshot.Providers.AddRange(tlgProviders);
                }

                snapshot.Providers = snapshot.Providers
                    .OrderBy(p => p.ProviderName, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(p => p.ProviderGuid, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                string fullPath = Path.GetFullPath(OutputPath);
                if (SnapshotIO.IsNdjsonPath(fullPath))
                {
                    SnapshotIO.WriteNdjson(snapshot, fullPath);
                }
                else
                {
                    SnapshotIO.WriteJson(snapshot, fullPath);
                }

                WriteVerbose($"Wrote {snapshot.Providers.Count} providers to {fullPath}");
                WriteObject(fullPath);
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "ExportEtwSnapshotError",
                    ErrorCategory.OperationStopped,
                    OutputPath));
            }
        }

        // Reads the full Windows version (Major.Minor.Build.UBR) from the registry.
        // Environment.OSVersion does not expose the UBR (Update Build Revision) -
        // it always returns 0 in the fourth slot - so we go to the source.
        private static string GetOSVersionString()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        int? major = key.GetValue("CurrentMajorVersionNumber") as int?;
                        int? minor = key.GetValue("CurrentMinorVersionNumber") as int?;
                        string buildStr = key.GetValue("CurrentBuildNumber") as string
                                       ?? key.GetValue("CurrentBuild") as string;
                        int? ubr = key.GetValue("UBR") as int?;

                        if (major.HasValue && minor.HasValue && !string.IsNullOrEmpty(buildStr))
                        {
                            return ubr.HasValue
                                ? $"{major.Value}.{minor.Value}.{buildStr}.{ubr.Value}"
                                : $"{major.Value}.{minor.Value}.{buildStr}";
                        }
                    }
                }
            }
            catch
            {
                // Fall through to Environment.OSVersion
            }
            return Environment.OSVersion.Version.ToString();
        }

        // Enumerates DLLs, EXEs, and SYSes directly under a directory, swallowing
        // access errors (locked or restricted files). Top-level only; the OS
        // directories we scan are flat enough that recursion isn't needed and
        // would just add WinSxS-style noise.
        private static IEnumerable<string> SafeEnumerateBinaries(string root)
        {
            if (!Directory.Exists(root)) yield break;
            foreach (var pattern in new[] { "*.dll", "*.exe", "*.sys" })
            {
                string[] hits;
                try
                {
                    hits = Directory.GetFiles(root, pattern, SearchOption.TopDirectoryOnly);
                }
                catch
                {
                    continue;
                }
                foreach (var h in hits) yield return h;
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Compare-EtwSnapshot diffs two snapshots produced by Export-EtwSnapshot.</para>
    /// <para type="description">Compare-EtwSnapshot loads two JSON snapshots (A and B) and returns a structured diff: providers that exist only in B (Added), only in A (Removed), or that exist in both but differ (Changed) — including added/removed/changed events keyed by Id+Version.</para>
    /// </summary>
    /// <example>
    /// <para> PS C:\> Compare-EtwSnapshot -PathA .\baseline.json -PathB .\new.json </para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Compare-EtwSnapshot .\vmA.json .\vmB.json </para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Compare-EtwSnapshot .\vmA.json .\vmB.json -ProviderName Threat </para>
    /// </example>
    [Cmdlet(VerbsData.Compare, "EtwSnapshot")]
    public class CompareEtwSnapshotCommand : Cmdlet
    {
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string PathA { get; set; }

        [Parameter(Mandatory = true, Position = 1)]
        [ValidateNotNullOrEmpty]
        public string PathB { get; set; }

        [Parameter(Mandatory = false)]
        public string ProviderName { get; set; }

        protected override void ProcessRecord()
        {
            try
            {
                var snapA = SnapshotIO.Read(PathA);
                var snapB = SnapshotIO.Read(PathB);

                var diff = new SnapshotDiff
                {
                    OSVersionA = snapA.OSVersion,
                    OSVersionB = snapB.OSVersion
                };

                var aProviders = snapA.Providers
                    .GroupBy(p => NormalizeGuid(p.ProviderGuid))
                    .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
                var bProviders = snapB.Providers
                    .GroupBy(p => NormalizeGuid(p.ProviderGuid))
                    .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

                foreach (var kvp in bProviders)
                {
                    if (!aProviders.ContainsKey(kvp.Key))
                    {
                        diff.ProvidersAdded.Add(kvp.Value);
                    }
                }

                foreach (var kvp in aProviders)
                {
                    if (!bProviders.ContainsKey(kvp.Key))
                    {
                        diff.ProvidersRemoved.Add(kvp.Value);
                    }
                }

                foreach (var kvp in aProviders)
                {
                    if (!bProviders.TryGetValue(kvp.Key, out var b))
                        continue;

                    var providerDiff = DiffProvider(kvp.Value, b);
                    if (providerDiff != null)
                    {
                        diff.ProvidersChanged.Add(providerDiff);
                    }
                }

                diff.ProvidersAdded = diff.ProvidersAdded
                    .OrderBy(p => p.ProviderName, StringComparer.OrdinalIgnoreCase).ToList();
                diff.ProvidersRemoved = diff.ProvidersRemoved
                    .OrderBy(p => p.ProviderName, StringComparer.OrdinalIgnoreCase).ToList();
                diff.ProvidersChanged = diff.ProvidersChanged
                    .OrderBy(p => p.ProviderName, StringComparer.OrdinalIgnoreCase).ToList();

                if (!string.IsNullOrEmpty(ProviderName))
                {
                    diff.ProvidersAdded = diff.ProvidersAdded
                        .Where(p => MatchesName(p.ProviderName)).ToList();
                    diff.ProvidersRemoved = diff.ProvidersRemoved
                        .Where(p => MatchesName(p.ProviderName)).ToList();
                    diff.ProvidersChanged = diff.ProvidersChanged
                        .Where(p => MatchesName(p.ProviderName)).ToList();
                }

                WriteObject(diff);
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "CompareEtwSnapshotError",
                    ErrorCategory.OperationStopped,
                    null));
            }
        }

        private static string NormalizeGuid(string guid)
        {
            if (string.IsNullOrEmpty(guid)) return string.Empty;
            return guid.Trim().Trim('{', '}').ToLowerInvariant();
        }

        private bool MatchesName(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            return name.IndexOf(ProviderName, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string EventKey(EventSnapshot e) => e.Id + ":" + e.Version;

        private static ProviderDiff DiffProvider(ProviderSnapshot a, ProviderSnapshot b)
        {
            var pd = new ProviderDiff
            {
                ProviderGuid = b.ProviderGuid,
                ProviderName = b.ProviderName
            };

            AddFieldChangeIfDifferent(pd.ProviderFieldsChanged, "ProviderName",
                a.ProviderName, b.ProviderName);
            AddFieldChangeIfDifferent(pd.ProviderFieldsChanged, "SchemaSource",
                a.SchemaSource, b.SchemaSource);
            AddFieldChangeIfDifferent(pd.ProviderFieldsChanged, "ResourceFilePath",
                a.ResourceFilePath, b.ResourceFilePath);

            var aEvents = (a.Events ?? new List<EventSnapshot>())
                .GroupBy(EventKey)
                .ToDictionary(g => g.Key, g => g.First());
            var bEvents = (b.Events ?? new List<EventSnapshot>())
                .GroupBy(EventKey)
                .ToDictionary(g => g.Key, g => g.First());

            foreach (var kvp in bEvents)
            {
                if (!aEvents.ContainsKey(kvp.Key))
                {
                    pd.EventsAdded.Add(kvp.Value);
                }
            }

            foreach (var kvp in aEvents)
            {
                if (!bEvents.ContainsKey(kvp.Key))
                {
                    pd.EventsRemoved.Add(kvp.Value);
                }
            }

            foreach (var kvp in aEvents)
            {
                if (!bEvents.TryGetValue(kvp.Key, out var bEvt))
                    continue;

                var ed = DiffEvent(kvp.Value, bEvt);
                if (ed != null)
                {
                    pd.EventsChanged.Add(ed);
                }
            }

            pd.EventsAdded = pd.EventsAdded.OrderBy(e => e.Id).ThenBy(e => e.Version).ToList();
            pd.EventsRemoved = pd.EventsRemoved.OrderBy(e => e.Id).ThenBy(e => e.Version).ToList();
            pd.EventsChanged = pd.EventsChanged.OrderBy(e => e.Id).ThenBy(e => e.Version).ToList();

            bool hasChanges = pd.ProviderFieldsChanged.Count > 0 ||
                              pd.EventsAdded.Count > 0 ||
                              pd.EventsRemoved.Count > 0 ||
                              pd.EventsChanged.Count > 0;

            return hasChanges ? pd : null;
        }

        private static EventDiff DiffEvent(EventSnapshot a, EventSnapshot b)
        {
            var ed = new EventDiff { Id = b.Id, Version = b.Version };

            AddFieldChangeIfDifferent(ed.Changes, "Level", a.Level, b.Level);
            AddFieldChangeIfDifferent(ed.Changes, "Opcode", a.Opcode, b.Opcode);
            AddFieldChangeIfDifferent(ed.Changes, "Task", a.Task, b.Task);
            AddFieldChangeIfDifferent(ed.Changes, "Keywords", a.Keywords, b.Keywords);
            AddFieldChangeIfDifferent(ed.Changes, "Description", a.Description, b.Description);
            AddFieldChangeIfDifferent(ed.Changes, "Template", a.Template, b.Template);

            var aKw = new HashSet<string>(a.KeywordNames ?? new List<string>(), StringComparer.Ordinal);
            var bKw = new HashSet<string>(b.KeywordNames ?? new List<string>(), StringComparer.Ordinal);
            if (!aKw.SetEquals(bKw))
            {
                ed.Changes.Add(new FieldChange
                {
                    Field = "KeywordNames",
                    A = string.Join(",", aKw.OrderBy(s => s)),
                    B = string.Join(",", bKw.OrderBy(s => s))
                });
            }

            return ed.Changes.Count > 0 ? ed : null;
        }

        private static void AddFieldChangeIfDifferent(List<FieldChange> list, string field, object a, object b)
        {
            if (Equals(a, b)) return;
            if (a is string sa && b is string sb && string.Equals(sa, sb, StringComparison.Ordinal)) return;
            list.Add(new FieldChange { Field = field, A = a, B = b });
        }
    }
}
