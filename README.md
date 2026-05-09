# ETWInspector
EtwInspector is a comprehensive Event Tracing for Windows (ETW) toolkit designed to simplify the enumeration of ETW providers and trace session properties.

Developed in C#, EtwInspector is easily accessible as a PowerShell module, making it user-friendly and convenient. This tool aims to be a one-stop solution for all ETW-related tasks—from discovery and inspection to trace capturing.

## Instructions
### PowerShell Gallery
Coming soon...

### Import Directly
1. Import EtwInspector via: 
```
PS > Import-Module EtwInspector.psd1
```
You may need to go to the file and press "unblock" if you get an error about importing the module and its depedencies. 

2. Get a list of available commands within the module: 
```
PS > Get-Command -Module EtwInspector

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Compare-EtwSnapshot                                1.0        EtwInspector
Cmdlet          Export-EtwSnapshot                                 1.0        EtwInspector
Cmdlet          Get-EtwProviders                                   1.0        EtwInspector
Cmdlet          Get-EtwSecurityDescriptor                          1.0        EtwInspector
Cmdlet          Get-EtwTraceSessions                               1.0        EtwInspector
Cmdlet          Start-EtwCapture                                   1.0        EtwInspector
Cmdlet          Stop-EtwCapture                                    1.0        EtwInspector
```

### Enumeration Steps

#### ETW Providers
`Get-EtwProviders` allows a user to enumerate Manifest, MOF, and Tracelogging providers. Depending on the provider type that is being queried, some functionality is more advanced then others. 

Example 1: Enumerating Manifest/MOF providers that have "Threat" in the provider name

```
PS > $EnumProviders = Get-EtwProviders -ProviderName Threat

PS > $EnumProviders

RegisteredProviders                     TraceloggingProviders
-------------------                     ---------------------
{Microsoft-Windows-Threat-Intelligence}


PS > $EnumProviders.RegisteredProviders

providerGuid       : f4e1897c-bb5d-5668-f1d8-040f4d8dd344
providerName       : Microsoft-Windows-Threat-Intelligence
resourceFilePath   : %SystemRoot%\system32\Microsoft-Windows-System-Events.dll
schemaSource       : Manifest
eventKeywords      : {KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL, KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER,
                     KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE, KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER...}
eventMetadata      : {1, 2, 2, 2...}
securityDescriptor : EtwInspector.Provider.Enumeration.EventTraceSecurity
```

Example 2: Enumerating Manifest providers that have "ReadVm" in a property field
```
PS > $EnumProviders = Get-EtwProviders -PropertyString ReadVm

PS > $EnumProviders

RegisteredProviders                     TraceloggingProviders
-------------------                     ---------------------
{Microsoft-Windows-Threat-Intelligence}


PS > $EnumProviders.RegisteredProviders

providerGuid       : f4e1897c-bb5d-5668-f1d8-040f4d8dd344
providerName       : Microsoft-Windows-Threat-Intelligence
resourceFilePath   : %SystemRoot%\system32\Microsoft-Windows-System-Events.dll
schemaSource       : Manifest
eventKeywords      : {KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL, KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER,
                     KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE, KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER...}
eventMetadata      : {1, 2, 2, 2...}
securityDescriptor : EtwInspector.Provider.Enumeration.EventTraceSecurity
```

Example 3: Enumerating tracelogging providers that exist in kerberos.dll

```
PS > $EnumProviders = Get-EtwProviders -ProviderType TraceLogging -FilePath C:\Windows\System32\kerberos.dll

PS > $EnumProviders.TraceloggingProviders.Providers | Select ProviderName, @{n='EventCount';e={$_.Events.Count}}

ProviderName                              EventCount
------------                              ----------
Microsoft.Windows.Security.Kerberos               52
Microsoft.Windows.Security.SspCommon              52
Microsoft.Windows.TlgAggregateInternal            52
```

> **TraceLogging caveat — events are not individually mapped to a provider.** TraceLogging metadata is embedded in the binary as a single blob containing every provider declared in the file followed by every event. The blob doesn't carry per-event provider IDs, and in every shipping Windows binary surveyed (1891 in System32 + drivers) events appear before providers in the stream, so the order can't be used to bind them either. As a result, every provider in a binary reports the binary's full event list. If you need a real binding, you have to do it via static analysis - the [TLGMapper](https://github.com/AsuNa-jp/TLGMapper) IDA plugin maps `TraceLoggingWrite` call sites back to their registered provider handles and is the most practical route today.

`Get-EtwTraceSessions` is also another cmdlet that allows someone to query trace sessions locally and remotely. You can query regular trace sessions, trace sessions that live in a data collector, and/or both. 


### Snapshots & Versioning
`Export-EtwSnapshot` and `Compare-EtwSnapshot` let you track changes to ETW providers over time — for example, to see what a Windows update changed about provider definitions, what new events were introduced, or which event metadata changed. Snapshot one machine (or take a snapshot before an update), snapshot another (or take a snapshot after the update), and diff the two.

#### Export-EtwSnapshot
Serializes Manifest, MOF, and TraceLogging providers on the local machine to a snapshot file. (WPP, the fourth ETW provider type, is not yet supported. MOF *providers* are listed but their *events* don't populate today - their event metadata isn't reliably present in WMI.)

**Default scan paths for TraceLogging** — TraceLogging metadata is compiled into individual binaries (DLLs/EXEs/SYS files) rather than registered with the OS, so finding it requires scanning files for the embedded `ETW0` signature. By default `Export-EtwSnapshot` walks:

- `C:\Windows\System32` (`*.dll`, `*.exe`)
- `C:\Windows\System32\drivers` (`*.sys`)

This adds roughly 30-60 seconds to the export. Use `-SkipTraceLogging` to skip the scan entirely, or `-ScanPath` to add additional directories (e.g. `C:\Program Files\YourApp`).

The output format is chosen by file extension:
- `.ndjson` or `.jsonl` — newline-delimited JSON. The first line is a header (`SchemaVersion`, `OSVersion`); each subsequent line is one full provider record. Recommended for diffing (line-based diff tools align cleanly per provider) and for stream-ingestion into a database or web service.
- any other extension — pretty-printed JSON, one big object containing the providers array. Easier to eyeball, larger on disk, harder to diff at scale.

```
PS > Export-EtwSnapshot C:\Snapshots\baseline.ndjson                                # Manifest + MOF + TraceLogging (default)
PS > Export-EtwSnapshot C:\Snapshots\fast.ndjson -SkipTraceLogging                  # Manifest + MOF only (~5s)
PS > Export-EtwSnapshot C:\Snapshots\full.ndjson -ScanPath 'C:\Program Files\App'   # also scan a custom dir
PS > Export-EtwSnapshot C:\Snapshots\baseline.json                                  # pretty JSON
```

The snapshot captures the OS version (`Major.Minor.Build.UBR`, read from the registry), provider GUID, name, schema source, resource file path or `Sources[]` array (TraceLogging providers can be embedded in multiple binaries; `Sources` lists every file the provider was discovered in), keywords, and per-event Id, Version, Level, Opcode, Task, Keywords, Description, and Template. Providers are sorted by name; events are sorted deterministically so two snapshots of identical state produce byte-stable output.

> **TraceLogging events are listed under every provider in the binary, not bound to a specific one.** The ETW0 metadata blob doesn't carry per-event provider IDs, so when a binary declares multiple TraceLogging providers all of them report the binary's full event list in the snapshot. To get a real per-event binding, do static analysis on the binary - [TLGMapper](https://github.com/AsuNa-jp/TLGMapper) is an IDA plugin that walks `TraceLoggingWrite` call sites and recovers the actual mapping.

> **Same name, different GUIDs.** TraceLogging provider identity in the snapshot is the GUID, not the name. The runtime normally derives the GUID deterministically from the upper-cased name (per the TraceLogging spec), but a developer can explicitly override it in `TRACELOGGING_DEFINE_PROVIDER`. When that happens you'll see multiple entries with the same `ProviderName` and different `ProviderGuid` values, each with its own `Sources[]` and events. Real example: `RDP` has four different GUIDs in System32 across different binaries.

#### Compare-EtwSnapshot
Loads two snapshots (A and B) and returns a structured diff. Both `.json` and `.ndjson`/`.jsonl` are accepted — and the two paths can use different formats (e.g. compare a legacy `.json` baseline against a new `.ndjson` snapshot).

```
PS > $diff = Compare-EtwSnapshot C:\Snapshots\baseline.json C:\Snapshots\current.json

PS > $diff

OSVersionA       : 10.0.26100.0
OSVersionB       : 10.0.26200.0
ProvidersAdded   : {Microsoft-Windows-NewProvider}
ProvidersRemoved : {}
ProvidersChanged : {Microsoft-Windows-Threat-Intelligence, Microsoft-Windows-Kernel-Process...}
```

For each provider in `ProvidersChanged`:
- `ProviderFieldsChanged` — provider-level field changes (e.g. `ResourceFilePath`), each with `A` and `B` values
- `EventsAdded` / `EventsRemoved` — events present in only one side, keyed by `Id`+`Version`
- `EventsChanged` — events in both sides whose metadata differs, with per-field `A`/`B` values

Filter the diff by a provider name substring with `-ProviderName` (case-insensitive):

```
PS > Compare-EtwSnapshot C:\Snapshots\baseline.json C:\Snapshots\current.json -ProviderName Threat
```

You can also persist a diff for review or sharing:

```
PS > $diff | ConvertTo-Json -Depth 20 | Set-Content C:\Snapshots\diff.json
```

#### Visual diffing with VS Code
For a side-by-side view of two snapshots, use NDJSON output and VS Code's built-in diff:

```
PS > code --diff C:\Snapshots\vmA.ndjson C:\Snapshots\vmB.ndjson
```

Because each provider lives on its own line, the diff aligns per provider with no cascading line offsets — even when providers are added or removed.


### Capture
EtwInspector also holds cmdlets, `Start-EtwCapture` and `Stop-EtwCapture` that allows a users to start and stop ETW trace sessions locally. These are fairly straight forward. Feel free to call `Get-Help Start-EtwCapture -Examples` for more details. 


## Previous Versions
If you prefer to use EtwInspector 1.0, which is written in C++ please visit the `v1.0` branch. 

## Feedback
If there are any features you would like to see, please don't hesitate to reach out. 

Thank you to the following people who were willing to test this tool and provide feedback: 
- Olaf Hartong
- Matt Graeber

## Resources/Nuget Packages:
* Fody
* Microsoft.Diagnostics.Tracing.TraceEvent
* XmlDoc2CmdletDoc

## Release Notes

v1.2.0
* `Export-EtwSnapshot` now includes TraceLogging providers by default. Scans `C:\Windows\System32` and `C:\Windows\System32\drivers` for the embedded ETW0 metadata, merges the same provider across the binaries it appears in, and records every source path on a new `Sources[]` field on the provider record
* New parameters: `-SkipTraceLogging` for the fast Manifest+MOF-only path, `-ScanPath <string[]>` to add custom directories to the TraceLogging scan
* Snapshot `SchemaVersion` bumped to `1.1` (adds the `Sources[]` field; older readers that ignore unknown fields keep working)

v1.1.0
* Added `Export-EtwSnapshot` and `Compare-EtwSnapshot` for diffing provider state across machines or across Windows updates
* Snapshots support both pretty JSON (`.json`) and newline-delimited JSON (`.ndjson` / `.jsonl`); NDJSON diffs cleanly per provider and is ideal for stream-ingestion
* Snapshot output is now deterministic — providers sorted by name, events sorted by `(Id, Version)` — so identical state produces byte-stable files
* Sped up MOF provider enumeration by indexing `.mof` files once instead of per-provider

v1.0.0
* Initial release of package
* Following Cmdlets: 
    * Get-EtwProviders 
    * Get-EtwSecurityDescriptor 
    * Get-EtwTraceSessions
    * Start-EtwCapture
    * Stop-EtwCapture


