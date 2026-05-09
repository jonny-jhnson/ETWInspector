using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;

namespace EtwInspector.Provider.Enumeration
{
    /// <summary>
    /// Container for the final "schema" that holds the result of parsing TraceLogging metadata.
    /// </summary>
    public class TraceLoggingSchema
    {
        public string FilePath { get; set; }
        public List<TraceLoggingProviderMetadata> Providers { get; set; } = new List<TraceLoggingProviderMetadata>();
        public List<TraceLoggingEventMetadata> Events { get; set; } = new List<TraceLoggingEventMetadata>();
    }

    public class RegisteredProviderSchema
    {
        public List<_PROVIDER_METADATA> Providers { get; set; } = new List<_PROVIDER_METADATA>();
    }

    /// <summary>
    /// Holds parsed provider info (to avoid name collision with System.Diagnostics.Eventing.Reader.ProviderMetadata).
    /// </summary>
    public class TraceLoggingProviderMetadata
    {
        public string ProviderGUID { get; set; }
        public string ProviderName { get; set; }
        public string ProviderGroupGUID { get; set; }
    }

    /// <summary>
    /// Holds parsed event metadata (channel, level, fields, etc.), renamed to avoid conflict with .NET's EventMetadata.
    /// </summary>
    public class TraceLoggingEventMetadata
    {
        public long EventId { get; set; }       // For _TlgBlobEvent2/3
        public byte Channel { get; set; }
        public byte Level { get; set; }
        public byte Opcode { get; set; }
        public string KeywordHex { get; set; }
        public string KeywordName { get; set; }
        public List<byte> Extension { get; set; } = new List<byte>();
        public string EventName { get; set; }
        public List<FieldMetadata> Fields { get; set; } = new List<FieldMetadata>();
        // Index into TraceLoggingSchema.Providers identifying which provider
        // owns this event. The blob walker tracks the most-recently-seen
        // provider blob; -1 means events appeared before any provider (orphans).
        public int ProviderIndex { get; set; } = -1;
    }

    /// <summary>
    /// Holds per-field metadata (InType, OutType, etc.).
    /// </summary>
    public class FieldMetadata
    {
        public string FieldName { get; set; }
        public string InType { get; set; }       // TlgIn
        public string OutType { get; set; }      // TlgOut (optional)
        public List<byte> Extension { get; set; } = new List<byte>();
        public ushort ValueCount { get; set; }
        public string TypeInfo { get; set; }
    }

    public class EventTraceSecurity : ObjectSecurity<EventTraceRights>
    {
        public EventTraceSecurity() : base(false, ResourceType.Service) { }
    }

    public class EnumerationResults
    {
        public List<_PROVIDER_METADATA> RegisteredProviders { get; set; } = new List<_PROVIDER_METADATA>();
        public TraceLoggingSchema TraceloggingProviders { get; set; }
    }

    public struct _SESSION_DATA
    {
        public string sessionName;
        public string logFileName;
        public string sessionGuid;
        public uint logFileMode;
    }

    //public struct _SECURITY_DESCRIPTOR
    //{
    //    public string Guid;
    //    public EventTraceSecurity SecurityDescriptor;
    //}

    public class _PROVIDER_METADATA
    {
        public string providerGuid { get; set; }
        public string providerName { get; set; }
        public string resourceFilePath { get; set; }
        public string schemaSource { get; set; }
        public IList<EventKeyword> eventKeywords { get; set; }
        public IEnumerable<EventMetadata> eventMetadata { get; set; }
        public EventTraceSecurity securityDescriptor { get; set; }
    }

    /// <summary>
    /// Enumeration for TlgIn types
    /// </summary>
    public enum TlgIn : byte
    {
        NULL = 0,
        UNICODESTRING = 1,
        ANSISTRING = 2,
        INT8 = 3,
        UINT8 = 4,
        INT16 = 5,
        UINT16 = 6,
        INT32 = 7,
        UINT32 = 8,
        INT64 = 9,
        UINT64 = 10,
        FLOAT = 11,
        DOUBLE = 12,
        BOOL32 = 13,
        BINARY = 14,
        GUID = 15,
        POINTER_UNSUPPORTED = 16,
        FILETIME = 17,
        SYSTEMTIME = 18,
        SID = 19,
        HEXINT32 = 20,
        HEXINT64 = 21,
        COUNTEDSTRING = 22,
        COUNTEDANSISTRING = 23,
        STRUCT = 24
    }

    /// <summary>
    /// Enumeration for TlgOut types
    /// </summary>
    public enum TlgOut : byte
    {
        NULL = 0,
        NOPRINT = 1,
        STRING = 2,
        BOOLEAN = 3,
        HEX = 4,
        PID = 5,
        TID = 6,
        PORT = 7,
        IPV4 = 8,
        IPV6 = 9,
        SOCKETADDRESS = 10,
        XML = 11,
        JSON = 12,
        WIN32ERROR = 13,
        NTSTATUS = 14,
        HRESULT = 15,
        FILETIME = 16,
        SIGNED = 17,
        UNSIGNED = 18,
        UTF8 = 35,
        PKCS7_WITH_TYPE_INFO = 36,
        CODE_POINTER = 37
    }

    [Flags]
    public enum EventTraceRights : int
    {
        WMIGuidQuery = 0x00000001,               // WMIGUID_QUERY
        WMIGuidSet = 0x00000002,                 // WMIGUID_SET
        WMIGuidNotification = 0x00000004,        // WMIGUID_NOTIFICATION
        WMIGuidReadDescription = 0x00000008,     // WMIGUID_READ_DESCRIPTION
        WMIGuidExecute = 0x00000010,             // WMIGUID_EXECUTE
        TracelogCreateRealtime = 0x00000020,     // TRACELOG_CREATE_REALTIME
        TracelogCreateOnDisk = 0x00000040,       // TRACELOG_CREATE_ONDISK
        TracelogGuidEnable = 0x00000080,         // TRACELOG_GUID_ENABLE
        TracelogAccessKernelLogger = 0x00000100, // TRACELOG_ACCESS_KERNEL_LOGGER
        TracelogLogEvent = 0x00000200,           // TRACELOG_LOG_EVENT
        TracelogAccessRealtime = 0x00000400,     // TRACELOG_ACCESS_REALTIME
        TracelogRegisterGuids = 0x00000800,      // TRACELOG_REGISTER_GUIDS
        TracelogJoinGroup = 0x00001000,          // TRACELOG_JOIN_GROUP

        // Standard access rights
        Delete = 0x00010000,                     // DELETE
        ReadControl = 0x00020000,                // READ_CONTROL
        WriteDac = 0x00040000,                   // WRITE_DAC
        WriteOwner = 0x00080000,                 // WRITE_OWNER
        Syncronize = 0x00100000,                 // SYNCHRONIZE
        StandardRightsRead = 0x00020000,         // STANDARD_RIGHTS_READ (same as ReadControl)

        // Access system security bit
        AccessSystemSecurity = 0x01000000,       // ACCESS_SYSTEM_SECURITY

        // Maximum allowed bit
        MaximumAllowed = 0x02000000,             // MAXIMUM_ALLOWED

        // Generic access rights
        GenericRead = unchecked((int)0x80000000), // GENERIC_READ
        GenericWrite = 0x40000000,               // GENERIC_WRITE
        GenericExecute = 0x20000000,             // GENERIC_EXECUTE
        GenericAll = 0x10000000,                 // GENERIC_ALL

        // Combined access rights
        ETWQuerySession = 0x0010000D,            // ETW_QUERY_SESSION
        ETWControlSession = 0x001000E2,          // ETW_CONTROL_SESSION
        ETWLogEvent = 0x00020A10,                // ETW_LOG_EVENT

        // Define WMIGuidAllAccess as a combination of other flags
        WMIGuidAllAccess = StandardRightsRead |
                   Syncronize |
                   WMIGuidQuery |
                   WMIGuidSet |
                   WMIGuidNotification |
                   WMIGuidReadDescription |
                   WMIGuidExecute |
                   TracelogCreateRealtime |
                   TracelogCreateOnDisk |
                   TracelogGuidEnable |
                   TracelogAccessKernelLogger |
                   TracelogLogEvent | // Same as TracelogCreateInproc based off of SDK
                   TracelogAccessRealtime |
                   TracelogRegisterGuids |
                   TracelogJoinGroup
    }

    public enum TRACE_QUERY_INFO_CLASS
    {
        TraceGuidQueryList = 0,
        TraceGuidQueryInfo = 1,
        TraceGuidQueryProcess = 2,
        TraceStackTracingInfo = 3,
        TraceSystemTraceEnableFlagsInfo = 4,
        TraceSampledProfileIntervalInfo = 5,
        TraceProfileSourceConfigInfo = 6,
        TraceProfileSourceListInfo = 7,
        TracePmcEventListInfo = 8,
        TracePmcCounterListInfo = 9,
        TraceSetDisallowList = 10,
        TraceVersionInfo = 11,
        TraceGroupQueryList = 12,
        TraceGroupQueryInfo = 13,
        TraceDisallowListQuery = 14,
        TraceInfoReserved15 = 15,
        TracePeriodicCaptureStateListInfo = 16,
        TracePeriodicCaptureStateInfo = 17,
        TraceProviderBinaryTracking = 18,
        TraceMaxLoggersQuery = 19,
        TraceLbrConfigurationInfo = 20,
        TraceLbrEventListInfo = 21,
        TraceMaxPmcCounterQuery = 22,
        TraceStreamCount = 23,
        TraceStackCachingInfo = 24,
        TracePmcCounterOwners = 25,
        TraceUnifiedStackCachingInfo = 26,
        TracePmcSessionInformation = 27,
        TraceContextRegisterInfo = 28,
        MaxTraceSetInfoClass = 29
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WNODE_HEADER
    {
        public uint BufferSize;        // Size of entire buffer (bytes)
        public uint ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;         // LARGE_INTEGER
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }



    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct EVENT_TRACE_PROPERTIES
    {
        public WNODE_HEADER Wnode;     // Embedded WNODE_HEADER
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public int NumberOfBuffers;
        public int FreeBuffers;
        public int EventsLost;
        public int BuffersWritten;
        public int LogBuffersLost;
        public int RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TRACE_GUID_PROPERTIES
    {
        public Guid Guid;            // The GUID of the trace provider
        public uint GuidType;        // Type of the GUID
        public uint LoggerId;        // Identifier for the logger
        public uint EnableLevel;     // Enable level for the provider
        public uint EnableFlags;     // Enable flags for the provider
        public byte IsEnable;        // Indicates whether the provider is enabled
    }

    public class TdhUtilities
    {
        [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
        public static extern uint TdhEnumerateProviders(IntPtr buffer, ref int bufferSize);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROVIDER_ENUMERATION_INFO
        {
            public int NumberOfProviders;
            public int Padding;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROVIDER_INFO
        {
            public Guid ProviderGuid;
            public int SchemaSource;
            public int ProviderNameOffset;
        }
    }


    public class SecurityDescriptorUtilities
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int EventAccessQuery(
            ref Guid Guid,
            IntPtr Buffer,
            ref int BufferSize
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr SecurityDescriptor,
            int RequestedStringSDRevision,
            uint SecurityInformation,
            out IntPtr StringSecurityDescriptor,
            out int StringSecurityDescriptorLen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool LocalFree(IntPtr hMem);

        public const int SDDL_REVISION_1 = 1;

        // Security information flags
        public const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        public const uint GROUP_SECURITY_INFORMATION = 0x00000002;
        public const uint DACL_SECURITY_INFORMATION = 0x00000004;
        public const uint SACL_SECURITY_INFORMATION = 0x00000008;
        public const uint LABEL_SECURITY_INFORMATION = 0x00000010;
        public const uint ATTRIBUTE_SECURITY_INFORMATION = 0x00000020;
        public const uint SCOPE_SECURITY_INFORMATION = 0x00000040;
        public const uint PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080;
        public const uint ACCESS_FILTER_SECURITY_INFORMATION = 0x00000100;
        public const uint BACKUP_SECURITY_INFORMATION = 0x00010000;

        public const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
        public const uint PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000;
        public const uint UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;
        public const uint UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000;

        public const uint FULL_SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION |
                                                     GROUP_SECURITY_INFORMATION |
                                                     DACL_SECURITY_INFORMATION |
                                                     SACL_SECURITY_INFORMATION |
                                                     LABEL_SECURITY_INFORMATION |
                                                     ATTRIBUTE_SECURITY_INFORMATION |
                                                     SCOPE_SECURITY_INFORMATION |
                                                     PROCESS_TRUST_LABEL_SECURITY_INFORMATION |
                                                     ACCESS_FILTER_SECURITY_INFORMATION |
                                                     BACKUP_SECURITY_INFORMATION;
    }

    /// <summary>
    /// Utilities for parsing TraceLogging metadata
    /// </summary>
    public class TraceLoggingUtilities
    {
        public static readonly Dictionary<ulong, string> KeywordMapping = new Dictionary<ulong, string>
        {
            { 140737488355328, "MS.CRITICALDATA" },
            { 70368744177664,  "MS.MEASURES" },
            { 35184372088832,  "MS.TELEMETRY" },
            { 562949953421312, "WINEVENT.TELEMETRY" }
        };

        /// <summary>
        /// Looks for "ETW0" signatures and parses every TraceLogging metadata
        /// block in the file. Each event is tagged with the index of the
        /// provider that owns it (the most-recently-seen provider blob in the
        /// same stream, since TraceLogging metadata interleaves provider and
        /// event blobs in declaration order).
        /// </summary>
        public static TraceLoggingSchema ParseTraceLoggingMetadata(string filePath)
        {
            var fullPath = Path.GetFullPath(filePath);
            var encoding = Encoding.GetEncoding(28591);
            var fileBytes = File.ReadAllBytes(fullPath);

            // Find every "ETW0" occurrence - some binaries have multiple discrete
            // metadata blocks. We try to parse each as its own TraceLogging block;
            // if the magic doesn't validate, we skip it (false positive).
            var offsets = FindAllOccurrences(fileBytes, new byte[] { 0x45, 0x54, 0x57, 0x30 });
            if (offsets.Count == 0) return null;

            TraceLoggingSchema schema = null;
            foreach (var offset in offsets)
            {
                var blockSchema = TryParseBlockAt(fileBytes, offset, fullPath, encoding);
                if (blockSchema == null) continue;
                if (schema == null)
                {
                    schema = blockSchema;
                }
                else
                {
                    // Merge subsequent blocks into the first schema. Re-base
                    // ProviderIndex so events keep pointing at the right provider.
                    int providerOffset = schema.Providers.Count;
                    schema.Providers.AddRange(blockSchema.Providers);
                    foreach (var e in blockSchema.Events)
                    {
                        if (e.ProviderIndex >= 0) e.ProviderIndex += providerOffset;
                        schema.Events.Add(e);
                    }
                }
            }
            return schema;
        }

        private static List<int> FindAllOccurrences(byte[] haystack, byte[] needle)
        {
            var hits = new List<int>();
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) hits.Add(i);
            }
            return hits;
        }

        private static TraceLoggingSchema TryParseBlockAt(byte[] fileBytes, int tlgSigValIndex, string fullPath, Encoding encoding)
        {
            using (var memoryStream = new MemoryStream(fileBytes))
            {
                memoryStream.Position = tlgSigValIndex;
                using (var br = new BinaryReader(memoryStream, encoding))
                {
                    // Verify the TraceLogging signature
                    var sigVal = Encoding.ASCII.GetString(br.ReadBytes(4));
                    if (memoryStream.Position + 12 > memoryStream.Length) return null;
                    ushort size = br.ReadUInt16();
                    byte version = br.ReadByte();
                    byte flags = br.ReadByte();
                    ulong magic = br.ReadUInt64();  // should be 0xBB8A052B88040E86

                    if (size != 16 || magic != 13513619316402294406UL)
                    {
                        return null; // Coincidental ETW0 occurrence, not a TraceLogging block
                    }

                    var schema = new TraceLoggingSchema { FilePath = fullPath };
                    int currentProviderIdx = -1;

                    // Read blob types until we hit 1 (_TlgBlobEnd)
                    byte blobType = br.ReadByte();
                    while (blobType != 1)
                    {
                        switch (blobType)
                        {
                            case 0: // _TlgBlobNone
                                break; // Just skip

                            case 2: // _TlgBlobProvider
                                schema.Providers.Add(ParseProviderBlob(br));
                                currentProviderIdx = schema.Providers.Count - 1;
                                break;

                            case 3: // _TlgBlobEvent3
                                {
                                    var e = ParseEvent3(br, tlgSigValIndex);
                                    e.ProviderIndex = currentProviderIdx;
                                    schema.Events.Add(e);
                                }
                                break;

                            case 4: // _TlgBlobProvider3
                                schema.Providers.Add(ParseProviderBlob3(br));
                                currentProviderIdx = schema.Providers.Count - 1;
                                break;

                            case 5: // _TlgBlobEvent2
                                {
                                    var e = ParseEvent2(br, tlgSigValIndex);
                                    e.ProviderIndex = currentProviderIdx;
                                    schema.Events.Add(e);
                                }
                                break;

                            case 6: // _TlgBlobEvent4
                                {
                                    var e = ParseEvent4(br);
                                    e.ProviderIndex = currentProviderIdx;
                                    schema.Events.Add(e);
                                }
                                break;

                            default:
                                // Unknown blob type - we've walked off the end of
                                // this metadata stream into other file content.
                                return schema;
                        }

                        if (memoryStream.Position >= memoryStream.Length) break;
                        blobType = br.ReadByte();
                    }

                    return schema;
                }
            }
        }

        /// <summary>
        /// Parse a _TlgBlobProvider (blobType=2).
        /// </summary>
        public static TraceLoggingProviderMetadata ParseProviderBlob(BinaryReader br)
        {
            // Next 2 => RemainingSize
            ushort remainingSize = br.ReadUInt16();

            string providerName = null;
            string providerGroupGuid = null;

            if (remainingSize > 0)
            {
                providerName = ReadNullTerminatedString(br);
                ushort remainingChunkSize = br.ReadUInt16();
                if (remainingChunkSize > 0)
                {
                    byte additionalInfoType = br.ReadByte();
                    if (additionalInfoType == 1)
                    {
                        var groupBytes = br.ReadBytes(16);
                        providerGroupGuid = new Guid(groupBytes).ToString();
                    }
                }
            }

            return new TraceLoggingProviderMetadata
            {
                ProviderGUID = null, // Not present in _TlgBlobProvider
                ProviderName = providerName,
                ProviderGroupGUID = providerGroupGuid
            };
        }

        /// <summary>
        /// Parse a _TlgBlobProvider3 (blobType=4).
        /// </summary>
        public static TraceLoggingProviderMetadata ParseProviderBlob3(BinaryReader br)
        {
            // First 16 => provider GUID
            var guidBytes = br.ReadBytes(16);
            var providerGuid = new Guid(guidBytes).ToString();

            // Next 2 => remainingSize
            ushort remainingSize = br.ReadUInt16();
            string providerName = null;
            string providerGroupGuid = null;

            if (remainingSize > 0)
            {
                providerName = ReadNullTerminatedString(br);

                if (br.BaseStream.Position < br.BaseStream.Length)
                {
                    long endPos = br.BaseStream.Position + (remainingSize - 2 - (providerName.Length + 1));
                    if (endPos <= br.BaseStream.Length)
                    {
                        if (br.BaseStream.Position < endPos)
                        {
                            ushort chunkSize = br.ReadUInt16();
                            if (chunkSize == 19)
                            {
                                byte traitVal = br.ReadByte();
                                if (traitVal == 1)
                                {
                                    var groupGuidBytes = br.ReadBytes(16);
                                    providerGroupGuid = new Guid(groupGuidBytes).ToString();
                                }
                            }
                            else
                            {
                                // Skip other chunks
                                br.BaseStream.Seek(chunkSize, SeekOrigin.Current);
                            }
                        }
                    }
                }
            }

            return new TraceLoggingProviderMetadata
            {
                ProviderGUID = providerGuid,
                ProviderName = providerName,
                ProviderGroupGUID = providerGroupGuid
            };
        }

        /// <summary>
        /// Parse a _TlgBlobEvent2 (blobType=5).
        /// </summary>
        public static TraceLoggingEventMetadata ParseEvent2(BinaryReader br, int tlgSigValIndex)
        {
            long eventId = br.BaseStream.Position - tlgSigValIndex;

            byte level = br.ReadByte();
            byte opcode = br.ReadByte();
            _ = br.ReadUInt16(); // Task (unused)

            ulong keywordVal = br.ReadUInt64();
            string keywordName = KeywordMapping.ContainsKey(keywordVal) ? KeywordMapping[keywordVal] : null;
            string keywordHex = "0x" + keywordVal.ToString("X16");

            ushort remainingSize = br.ReadUInt16();

            var evt = new TraceLoggingEventMetadata
            {
                EventId = eventId,
                Channel = 0xB,
                Level = level,
                Opcode = opcode,
                KeywordHex = keywordHex,
                KeywordName = keywordName
            };

            if (remainingSize > 0)
            {
                long endPos = br.BaseStream.Position + (remainingSize - 2);

                // Extension array
                if (br.BaseStream.Position < endPos)
                {
                    byte extVal;
                    do
                    {
                        extVal = br.ReadByte();
                        evt.Extension.Add(extVal);
                    }
                    while ((extVal & 0x80) != 0 && br.BaseStream.Position < endPos);
                }

                // Event name
                if (br.BaseStream.Position < endPos)
                {
                    evt.EventName = ReadNullTerminatedString(br);
                }

                // Fields
                while (br.BaseStream.Position < endPos)
                {
                    var field = ParseFieldMetadata(br, endPos);
                    if (field == null) break;
                    evt.Fields.Add(field);
                }
            }

            return evt;
        }

        /// <summary>
        /// Parse a _TlgBlobEvent3 (blobType=3).
        /// </summary>
        public static TraceLoggingEventMetadata ParseEvent3(BinaryReader br, int tlgSigValIndex)
        {
            long eventId = br.BaseStream.Position - tlgSigValIndex;

            byte channel = br.ReadByte();  // typically 11
            byte level = br.ReadByte();
            byte opcode = br.ReadByte();

            ulong keywordVal = br.ReadUInt64();
            string keywordName = KeywordMapping.ContainsKey(keywordVal) ? KeywordMapping[keywordVal] : null;
            string keywordHex = "0x" + keywordVal.ToString("X16");

            ushort remainingSize = br.ReadUInt16();

            var evt = new TraceLoggingEventMetadata
            {
                EventId = eventId,
                Channel = channel,
                Level = level,
                Opcode = opcode,
                KeywordHex = keywordHex,
                KeywordName = keywordName
            };

            if (remainingSize > 0)
            {
                long endPos = br.BaseStream.Position + (remainingSize - 2);

                // Extension
                if (br.BaseStream.Position < endPos)
                {
                    byte extVal;
                    do
                    {
                        extVal = br.ReadByte();
                        evt.Extension.Add(extVal);
                    }
                    while ((extVal & 0x80) != 0 && br.BaseStream.Position < endPos);
                }

                // Event name
                if (br.BaseStream.Position < endPos)
                {
                    evt.EventName = ReadNullTerminatedString(br);
                }

                // Fields
                while (br.BaseStream.Position < endPos)
                {
                    var field = ParseFieldMetadata(br, endPos);
                    if (field == null) break;
                    evt.Fields.Add(field);
                }
            }

            return evt;
        }

        /// <summary>
        /// Parse a _TlgBlobEvent4 (blobType=6). EventId is always 0.
        /// </summary>
        public static TraceLoggingEventMetadata ParseEvent4(BinaryReader br)
        {
            byte channel = br.ReadByte(); // typically 11
            byte level = br.ReadByte();
            byte opcode = br.ReadByte();

            ulong keywordVal = br.ReadUInt64();
            string keywordName = KeywordMapping.ContainsKey(keywordVal) ? KeywordMapping[keywordVal] : null;
            string keywordHex = "0x" + keywordVal.ToString("X16");

            ushort remainingSize = br.ReadUInt16();

            var evt = new TraceLoggingEventMetadata
            {
                EventId = 0,
                Channel = channel,
                Level = level,
                Opcode = opcode,
                KeywordHex = keywordHex,
                KeywordName = keywordName
            };

            if (remainingSize > 0)
            {
                long endPos = br.BaseStream.Position + (remainingSize - 2);

                // Extension
                if (br.BaseStream.Position < endPos)
                {
                    byte extVal;
                    do
                    {
                        extVal = br.ReadByte();
                        evt.Extension.Add(extVal);
                    }
                    while ((extVal & 0x80) != 0 && br.BaseStream.Position < endPos);
                }

                // Event name
                if (br.BaseStream.Position < endPos)
                {
                    evt.EventName = ReadNullTerminatedString(br);
                }

                // Fields
                while (br.BaseStream.Position < endPos)
                {
                    var field = ParseFieldMetadata(br, endPos);
                    if (field == null) break;
                    evt.Fields.Add(field);
                }
            }

            return evt;
        }

        /// <summary>
        /// Parse field metadata from an event (common to _TlgBlobEvent2, 3, 4).
        /// </summary>
        public static FieldMetadata ParseFieldMetadata(BinaryReader br, long endPos)
        {
            if (br.BaseStream.Position >= endPos)
                return null;

            string fieldName = ReadNullTerminatedString(br);
            if (string.IsNullOrEmpty(fieldName))
                return null;

            byte inTypeVal = br.ReadByte();
            byte inTypeMask = 31; // 0x1F

            string outType = null;
            List<byte> extensionList = null;

            // If top bit => outType is present
            if ((inTypeVal & 128) != 0)
            {
                byte outTypeVal = br.ReadByte();

                if ((outTypeVal & 128) != 0)
                {
                    extensionList = new List<byte>();
                    byte extVal;
                    do
                    {
                        extVal = br.ReadByte();
                        extensionList.Add(extVal);
                    }
                    while ((extVal & 0x80) != 0 && br.BaseStream.Position < endPos);
                }

                byte maskedOut = (byte)(outTypeVal & 0x7F);
                if (Enum.IsDefined(typeof(TlgOut), maskedOut))
                {
                    outType = ((TlgOut)maskedOut).ToString();
                }
                else
                {
                    outType = $"Unknown(0x{maskedOut:X2})";
                }
            }

            ushort valueCount = 0;
            string typeInfo = null;

            // If (inTypeVal & 32) => ValueCount is present
            if ((inTypeVal & 32) != 0)
            {
                valueCount = br.ReadUInt16();
            }

            // If ((inTypeVal & (32|64)) == (32|64)) => TypeInfo is present
            if ((inTypeVal & (32 | 64)) == (32 | 64))
            {
                ushort typeInfoSize = br.ReadUInt16();
                if (typeInfoSize > 0 && (br.BaseStream.Position + typeInfoSize) <= endPos)
                {
                    var raw = br.ReadChars(typeInfoSize);
                    typeInfo = new string(raw);
                }
            }

            // Mask out actual TlgIn
            byte maskedInVal = (byte)(inTypeVal & inTypeMask);
            string inTypeStr;
            if (Enum.IsDefined(typeof(TlgIn), maskedInVal))
            {
                inTypeStr = ((TlgIn)maskedInVal).ToString();
            }
            else
            {
                inTypeStr = $"Unknown(0x{maskedInVal:X2})";
            }

            return new FieldMetadata
            {
                FieldName = fieldName,
                InType = inTypeStr,
                OutType = outType,
                Extension = extensionList ?? new List<byte>(),
                ValueCount = valueCount,
                TypeInfo = typeInfo
            };
        }

        /// <summary>
        /// Read a null-terminated string (ASCII or single-byte) from the BinaryReader.
        /// </summary>
        public static string ReadNullTerminatedString(BinaryReader br)
        {
            var sb = new StringBuilder();
            byte b;
            while ((b = br.ReadByte()) != 0)
            {
                sb.Append((char)b);
            }
            return sb.ToString();
        }
    }


    /// <summary>
    /// <para type="synopsis">Get-EtwProviders enumerates ETW Providers.</para>
    /// <para type="description"> Get-EtwProviders enumerates ETW Providers. It can enumerate standard providers (Manifest or MOF) and TraceLogging providers.</para>
    /// </summary>
    /// <example>
    /// <para> PS C:\> Get-EtwProviders -ProviderType MOF</para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Get-EtwProviders -ProviderType Manifest, MOF -ProviderName Kerberos </para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Get-EtwProviders -ProviderType Manifest, MOF, TraceLogging -ProviderName Kerberos -FilePath C:\Windows\System32\kerberos.dll </para>
    /// </example>

    [Cmdlet(VerbsCommon.Get, "EtwProviders")]
    public class GetEtwProvidersCommand : Cmdlet
    {
        [Parameter()]
        public string ProviderName { get; set; }

        [Parameter(Mandatory = false)]
        public string ProviderGUID { get; set; }

        [Parameter()]
        [ValidateSet("Manifest", "MOF", "TraceLogging")]
        public string[] ProviderType { get; set; } = new string[] { "MOF", "Manifest" };

        [Parameter(Mandatory = false)]
        public string FilePath { get; set; }

        [Parameter(Mandatory = false)]
        public string PropertyString { get; set; }

        [Parameter(Mandatory = false)]
        [ValidateSet("FullStringSearch", "KeywordSearch", "MetadataSearch")]
        public string SearchType { get; set; } = "FullStringSearch";

        protected override void ProcessRecord()
        {
            var results = new EnumerationResults();
            try
            {
                if(ProviderType.Contains("TraceLogging"))
                {
                    results.TraceloggingProviders = ProcessTraceLoggingProvider();
                }
                if(ProviderType.Contains("Manifest") && ProviderType.Contains("MOF"))
                {
                    results.RegisteredProviders = (ProcessStandardProviders("All"));
                }
                else if(ProviderType.Contains("Manifest"))
                {
                    results.RegisteredProviders = (ProcessStandardProviders("Manifest"));
                }
                else if (ProviderType.Contains("MOF"))
                {
                    results.RegisteredProviders = (ProcessStandardProviders("MOF"));
                }

                WriteObject(results);
                
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "GetEtwProvidersError",
                    ErrorCategory.OperationStopped,
                    null));
            }
        }

        private TraceLoggingSchema ProcessTraceLoggingProvider()
        {
            if (string.IsNullOrEmpty(FilePath))
            {
                WriteWarning("Tracelogging providers will not be enumerated. FilePath is required when enumerating TraceLogging Providers\n");
                return null;
            }

            var schema = TraceLoggingUtilities.ParseTraceLoggingMetadata(FilePath);
            return schema;
        }

        public List<_PROVIDER_METADATA> ProcessStandardProviders(string SchemaSource)
        {
            var providers = new List<_PROVIDER_METADATA>();
            // Get required buffer size
            int bufferSize = 0;
            uint status = TdhUtilities.TdhEnumerateProviders(IntPtr.Zero, ref bufferSize);

            if (status != 0x7A) // ERROR_INSUFFICIENT_BUFFER
            {
                throw new Exception($"Failed to get buffer size for provider enumeration. Status: 0x{status:X}");
            }

            IntPtr buffer = IntPtr.Zero;
            try
            {
                // Allocate memory and enumerate providers
                buffer = Marshal.AllocHGlobal(bufferSize);
                status = TdhUtilities.TdhEnumerateProviders(buffer, ref bufferSize);

                if (status != 0)
                {
                    throw new Exception($"Failed to enumerate ETW providers. Status: 0x{status:X}");
                }

                // Process providers
                providers = ParseProviderInfo(buffer);

                // Apply filters
                providers = FilterProviders(providers, SchemaSource);

                // Output results
                return providers;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private List<_PROVIDER_METADATA> ParseProviderInfo(IntPtr buffer)
        {
            var enumerationInfo = Marshal.PtrToStructure<TdhUtilities.PROVIDER_ENUMERATION_INFO>(buffer);
            var providerList = new List<_PROVIDER_METADATA>();

            IntPtr currentPtr = IntPtr.Add(buffer, Marshal.SizeOf<TdhUtilities.PROVIDER_ENUMERATION_INFO>());

            for (int i = 0; i < enumerationInfo.NumberOfProviders; i++)
            {
                var providerInfo = Marshal.PtrToStructure<TdhUtilities.PROVIDER_INFO>(currentPtr);
                IntPtr providerNamePtr = IntPtr.Add(buffer, providerInfo.ProviderNameOffset);
                string providerName = Marshal.PtrToStringUni(providerNamePtr);
                string schemaSource = (providerInfo.SchemaSource == 1) ? "MOF" : "Manifest";

                var providerMetadata = new _PROVIDER_METADATA
                {
                    providerGuid = providerInfo.ProviderGuid.ToString(),
                    providerName = providerName,
                    schemaSource = schemaSource,
                    resourceFilePath = null,
                    eventKeywords = null,
                    eventMetadata = null,
                    securityDescriptor = null
                };

                // If manifest-based, retrieve additional details
                if (providerInfo.SchemaSource == 0)
                {
                    EnrichProviderWithManifestData(providerMetadata, providerName);

                    if (providerMetadata.resourceFilePath == null)
                    {
                        GetInformationFromRegistry(providerMetadata);
                    }
                }
                else
                {
                    EnrichProviderWithMOFData(providerMetadata, providerName);
                }
                providerList.Add(providerMetadata);
                currentPtr = IntPtr.Add(currentPtr, Marshal.SizeOf<TdhUtilities.PROVIDER_INFO>());
            }

            return providerList;
        }

        private void SafeWriteVerbose(string message)
        {
            try { WriteVerbose(message); }
            catch (NotImplementedException) { /* invoked outside a pipeline */ }
        }

        private Dictionary<string, string> _mofGuidIndex;

        private Dictionary<string, string> GetMofGuidIndex()
        {
            if (_mofGuidIndex != null) return _mofGuidIndex;

            var index = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var guidPattern = new System.Text.RegularExpressions.Regex(
                @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                System.Text.RegularExpressions.RegexOptions.Compiled);

            try
            {
                var mofFiles = Directory.GetFiles(@"C:\Windows\System32\wbem", "*.mof", SearchOption.AllDirectories);
                foreach (var file in mofFiles)
                {
                    try
                    {
                        var content = File.ReadAllText(file);
                        foreach (System.Text.RegularExpressions.Match m in guidPattern.Matches(content))
                        {
                            if (!index.ContainsKey(m.Value))
                            {
                                index[m.Value] = file;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        SafeWriteVerbose($"Skipping MOF file {file}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                SafeWriteVerbose($"Could not enumerate MOF directory: {ex.Message}");
            }

            _mofGuidIndex = index;
            return _mofGuidIndex;
        }

        private void EnrichProviderWithMOFData(_PROVIDER_METADATA providerMetadata, string providerName)
        {
            try
            {
                var index = GetMofGuidIndex();
                if (index.TryGetValue(providerMetadata.providerGuid, out var file))
                {
                    providerMetadata.resourceFilePath = file;
                }
            }
            catch (EventLogException)
            {
                SafeWriteVerbose($"Could not load MOF data for provider: {providerName}.");
            }
            catch (Exception ex)
            {
                SafeWriteVerbose($"Error loading MOF data for {providerName}: {ex.Message}");
            }
        }

        private void EnrichProviderWithManifestData(_PROVIDER_METADATA providerMetadata, string providerName)
        {
            try
            {
                using (ProviderMetadata provider = new ProviderMetadata(providerName))
                {
                    providerMetadata.resourceFilePath = provider.ResourceFilePath;
                    providerMetadata.eventKeywords = provider.Keywords.ToList();
                    providerMetadata.eventMetadata = provider.Events.ToList();
                }
                providerMetadata.securityDescriptor = GetSecurityDescriptorCommand.GetEtwSecurityDescriptor(providerMetadata.providerGuid);

            }
            catch (EventLogException)
            {
                SafeWriteVerbose($"Could not load manifest for provider: {providerName}");
            }
            catch (Exception ex)
            {
                SafeWriteVerbose($"Error loading metadata for {providerName}: {ex.Message}");
            }
        }

        private void GetInformationFromRegistry(_PROVIDER_METADATA providerMetadata)
        {
            string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{" + providerMetadata.providerGuid + "}";

            using (var key = Registry.LocalMachine.OpenSubKey(keyPath, false))
            {
                if (key != null)
                {
                    var value = key.GetValue("ResourceFileName");
                    if (value != null)
                    {
                        providerMetadata.resourceFilePath = value.ToString();
                    }
                }
            }
        }

        private bool StringMatchesDescription(EventMetadata metadata, string searchString)
        {
            return !string.IsNullOrEmpty(metadata.Description) &&
                   metadata.Description.IndexOf(searchString, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool StringMatchesTemplate(EventMetadata metadata, string searchString)
        {
            if (string.IsNullOrEmpty(metadata.Template))
            {
                return false;
            }

            try
            {
                var xmlDoc = new System.Xml.XmlDocument();
                xmlDoc.LoadXml(metadata.Template);

                var dataNodes = xmlDoc.GetElementsByTagName("data");
                foreach (System.Xml.XmlNode node in dataNodes)
                {
                    var nameAttr = node.Attributes?["name"];
                    if (nameAttr != null)
                    {
                        if (nameAttr.Value.IndexOf(searchString, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            return true;
                        }
                    }
                }
            }
            catch (System.Xml.XmlException)
            {
                return false;
            }

            return false;
        }

        private bool StringMatchesKeywords(EventMetadata metadata, string searchString)
        {
            if (metadata.Keywords == null)
            {
                return false;
            }

            return metadata.Keywords.Any(keyword =>
                !string.IsNullOrEmpty(keyword.Name) &&
                keyword.Name.IndexOf(searchString, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private List<_PROVIDER_METADATA> FilterProviders(List<_PROVIDER_METADATA> providerList, string SchemaSource)
        {
            // Filter by ProviderName if specified
            if (!string.IsNullOrEmpty(ProviderName))
            {
                providerList = providerList.FindAll(p => p.providerName.ToLower().Contains(ProviderName.ToLower()));
            }

            // Filter by ProviderGUID if specified
            if (!string.IsNullOrEmpty(ProviderGUID))
            {
                providerList = providerList.FindAll(p => p.providerGuid.Equals(ProviderGUID, StringComparison.OrdinalIgnoreCase));
            }

            if (SchemaSource != "All")
            {
                providerList = providerList.FindAll(p => p.schemaSource.Equals(SchemaSource, StringComparison.OrdinalIgnoreCase));
            }
         
            if (!string.IsNullOrEmpty(PropertyString))
            {
                if (SearchType == "FullStringSearch")
                {
                    providerList = providerList.FindAll(p => p.eventMetadata != null && p.eventMetadata.Any(e => StringMatchesDescription(e, PropertyString) || StringMatchesKeywords(e, PropertyString) || StringMatchesTemplate(e, PropertyString)));
                }
                if (SearchType == "KeywordSearch")
                {
                    providerList = providerList.FindAll(p => p.eventMetadata != null && p.eventMetadata.Any(e => StringMatchesKeywords(e, PropertyString)));
                }
                if (SearchType == "MetadataSearch")
                {
                    providerList = providerList.FindAll(p => p.eventMetadata != null && p.eventMetadata.Any(e => StringMatchesDescription(e, PropertyString) || StringMatchesTemplate(e, PropertyString)));
                }
            }

            return providerList;
        }
    }

    /// <summary>
    /// <para type="synopsis">Get-EtwSecurityDescriptor enumerates an ETW security descriptor.</para>
    /// <para type="description"> Get-EtwSecurityDescriptor enumerates an ETW security descriptor. Right now, this is only supported for Manifest-based providers. </para>
    /// </summary>
    /// <example>
    /// <para> PS C:\> Get-EtwSecurityDescriptor -Guid "54849625-5478-4994-a5ba-3e3b0328c30d"</para>
    /// </example>
    /// <example>
    /// <para> PS C:\> Get-EtwSecurityDescriptor -Guid $result.RegisteredProviders.providerGuid </para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "EtwSecurityDescriptor")]
    public class GetSecurityDescriptorCommand : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true)]
        public string Guid { get; set; }
        protected override void ProcessRecord()
        {
            try
            {
                EventTraceSecurity securityDescriptor = GetEtwSecurityDescriptor(Guid);
                if (securityDescriptor == null)
                {
                    Console.WriteLine("Empty SD\n");
                }
                else
                {
                    WriteObject(securityDescriptor);
                }
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(
                    ex,
                    "GeneralError",
                    ErrorCategory.NotSpecified,
                    Guid));
            }
        }

        public static EventTraceSecurity GetEtwSecurityDescriptor(string guidString)
        {
            if (string.IsNullOrEmpty(guidString))
            {
                throw new ArgumentException("GUID cannot be null or empty", nameof(guidString));
            }

            if (!System.Guid.TryParse(guidString, out Guid eventGuid))
            {
                throw new ArgumentException("Invalid GUID format.", nameof(guidString));
            }

            int bufferSize = 0;
            int result = SecurityDescriptorUtilities.EventAccessQuery(ref eventGuid, IntPtr.Zero, ref bufferSize);

            if (result != 234 && result != 122)
            {
                throw new InvalidOperationException($"EventAccessQuery failed with error code: {result}");
            }

            // Allocate memory and query the security descriptor
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                result = SecurityDescriptorUtilities.EventAccessQuery(ref eventGuid, buffer, ref bufferSize);

                if (result != 0) // Not ERROR_SUCCESS
                {
                    throw new InvalidOperationException($"EventAccessQuery failed with error code: {result}");
                }

                // Convert binary security descriptor to SDDL string (with FULL security info)
                if (!SecurityDescriptorUtilities.ConvertSecurityDescriptorToStringSecurityDescriptor(
                        buffer, SecurityDescriptorUtilities.SDDL_REVISION_1, SecurityDescriptorUtilities.FULL_SECURITY_INFORMATION, out IntPtr sddlPtr, out int _))
                {
                    throw new InvalidOperationException("Failed to convert binary security descriptor to full SDDL.");
                }

                string sddl = Marshal.PtrToStringUni(sddlPtr);
                SecurityDescriptorUtilities.LocalFree(sddlPtr);

                if (string.IsNullOrWhiteSpace(sddl))
                {
                    throw new InvalidOperationException("Retrieved empty or invalid security descriptor.");
                }

                // Create and set the security descriptor
                EventTraceSecurity security = new EventTraceSecurity();
                security.SetSecurityDescriptorSddlForm(sddl);

                return security;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}