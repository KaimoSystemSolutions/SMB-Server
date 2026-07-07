using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;

namespace Smb.Tests;

/// <summary>Helper functions for building test messages (request side, which the lib itself does not serialize).</summary>
internal static class TestHelpers
{
    /// <summary>Builds a 64-byte SMB2 SYNC request header.</summary>
    public static byte[] BuildHeader(SmbCommand command, ulong messageId, ulong sessionId = 0,
        uint treeId = 0, Smb2HeaderFlags flags = Smb2HeaderFlags.None, ushort creditRequest = 1)
    {
        var header = new Smb2Header
        {
            Command = command,
            MessageId = messageId,
            SessionId = sessionId,
            TreeId = treeId,
            Flags = flags,
            CreditRequestResponse = creditRequest,
            CreditCharge = 1,
        };
        return header.ToArray();
    }

    /// <summary>Builds a complete NEGOTIATE request (header + body), optionally with 3.1.1 contexts.</summary>
    public static byte[] BuildNegotiateRequest(
        IReadOnlyList<SmbDialect> dialects,
        SmbSecurityMode securityMode = SmbSecurityMode.SigningEnabled,
        IReadOnlyList<SmbCipherId>? ciphers = null,
        IReadOnlyList<SmbSigningAlgorithmId>? signingAlgs = null,
        bool includePreauthContext = true)
    {
        bool with311 = dialects.Contains(SmbDialect.Smb311);
        var body = new GrowableWriter(128);

        body.WriteUInt16(36);                          // StructureSize
        body.WriteUInt16((ushort)dialects.Count);      // DialectCount
        body.WriteUInt16((ushort)securityMode);        // SecurityMode
        body.WriteUInt16(0);                           // Reserved
        body.WriteUInt32((uint)Smb2Capabilities.LargeMtu); // Capabilities
        body.WriteBytes(new byte[16]);                 // ClientGuid

        int negCtxOffsetPos = body.Position;
        body.WriteUInt32(0);                           // NegotiateContextOffset (patch)
        body.WriteUInt16(0);                           // NegotiateContextCount (patch)
        body.WriteUInt16(0);                           // Reserved2

        foreach (SmbDialect d in dialects) body.WriteUInt16((ushort)d);

        var contexts = new List<NegotiateContext>();
        if (with311)
        {
            if (includePreauthContext)
                contexts.Add(new PreauthIntegrityContext
                {
                    HashAlgorithms = [PreauthHashAlgorithm.Sha512],
                    Salt = new byte[32],
                });
            if (ciphers is not null)
                contexts.Add(new EncryptionContext { Ciphers = ciphers });
            if (signingAlgs is not null)
                contexts.Add(new SigningContext { Algorithms = signingAlgs });
        }

        if (contexts.Count > 0)
        {
            // 8-byte alignment relative to message start (Header = 64, so Body-Pos + 64).
            PadToAbs8(body);
            int ctxStartAbs = Smb2Header.Size + body.Position;
            body.PatchUInt32(negCtxOffsetPos, (uint)ctxStartAbs);
            body.PatchUInt16(negCtxOffsetPos + 4, (ushort)contexts.Count);

            for (int i = 0; i < contexts.Count; i++)
            {
                if (i > 0) PadToAbs8(body);
                contexts[i].Write(body);
            }
        }

        byte[] header = BuildHeader(SmbCommand.Negotiate, 0);
        return Concat(header, body.ToArray());
    }

    /// <summary>Baut einen SESSION_SETUP-Request (Header + Body) mit gegebenem Token.</summary>
    public static byte[] BuildSessionSetupRequest(ulong messageId, ulong sessionId, byte[] token,
        Smb2HeaderFlags flags = Smb2HeaderFlags.None, byte[]? signingKey = null,
        SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac,
        SessionSetupFlags sessionFlags = SessionSetupFlags.None)
    {
        var body = new GrowableWriter(64);
        body.WriteUInt16(25);                 // StructureSize
        body.WriteByte((byte)sessionFlags);   // Flags (0x01 = SMB2_SESSION_FLAG_BINDING)
        body.WriteByte((byte)SmbSecurityMode.SigningEnabled); // SecurityMode
        body.WriteUInt32((uint)Smb2Capabilities.None);        // Capabilities
        body.WriteUInt32(0);                  // Channel
        int secOffPos = body.Position;
        body.WriteUInt16(0);                  // SecurityBufferOffset (patch)
        body.WriteUInt16((ushort)token.Length);
        body.WriteUInt64(0);                  // PreviousSessionId
        int bufStart = body.Position;
        body.WriteBytes(token);
        body.PatchUInt16(secOffPos, (ushort)(Smb2Header.Size + bufStart));

        byte[] header = BuildHeader(SmbCommand.SessionSetup, messageId, sessionId, flags: flags);
        byte[] message = Concat(header, body.ToArray());

        if (signingKey is not null)
            SignInPlace(message, messageId, signingKey, alg);
        return message;
    }

    /// <summary>Baut einen TREE_CONNECT-Request zu <c>\\server\share</c>.</summary>
    public static byte[] BuildTreeConnectRequest(ulong messageId, ulong sessionId, string uncPath,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(uncPath);
        var body = new GrowableWriter(32);
        body.WriteUInt16(9);                  // StructureSize
        body.WriteUInt16(0);                  // Flags/Reserved
        int pathOffPos = body.Position;
        body.WriteUInt16(0);                  // PathOffset (patch)
        body.WriteUInt16((ushort)pathBytes.Length);
        int pathStart = body.Position;
        body.WriteBytes(pathBytes);
        body.PatchUInt16(pathOffPos, (ushort)(Smb2Header.Size + pathStart));

        byte[] header = BuildHeader(SmbCommand.TreeConnect, messageId, sessionId);
        byte[] message = Concat(header, body.ToArray());
        if (signingKey is not null) SignInPlace(message, messageId, signingKey, alg);
        return message;
    }

    /// <summary>Baut einen LOGOFF-Request (StructureSize 4), optional signiert.</summary>
    public static byte[] BuildLogoffRequest(ulong messageId, ulong sessionId,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new byte[4];
        var w = new SpanWriter(body);
        w.WriteUInt16(4); // StructureSize
        w.WriteUInt16(0); // Reserved

        byte[] header = BuildHeader(SmbCommand.Logoff, messageId, sessionId);
        byte[] message = Concat(header, body);
        if (signingKey is not null) SignInPlace(message, messageId, signingKey, alg);
        return message;
    }

    /// <summary>Baut einen ECHO-Request, optional signiert.</summary>
    public static byte[] BuildEchoRequest(ulong messageId, ulong sessionId = 0,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new byte[4];
        var w = new SpanWriter(body);
        w.WriteUInt16(4);
        w.WriteUInt16(0);

        byte[] header = BuildHeader(SmbCommand.Echo, messageId, sessionId);
        byte[] message = Concat(header, body);
        if (signingKey is not null) SignInPlace(message, messageId, signingKey, alg);
        return message;
    }

    /// <summary>Builds a CREATE request (opens a file/directory). <paramref name="requestedOplockLevel"/>
    /// sets the RequestedOplockLevel byte (0=None, 1=LevelII, 8=Exclusive, 9=Batch).</summary>
    public static byte[] BuildCreateRequest(ulong messageId, ulong sessionId, uint treeId, string name,
        uint desiredAccess, uint disposition, uint options, byte[]? signingKey = null,
        SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac, byte requestedOplockLevel = 0,
        uint shareAccess = 0x00000007, byte[]? createContexts = null)
    {
        byte[] nameBytes = System.Text.Encoding.Unicode.GetBytes(name);
        var body = new GrowableWriter(64 + nameBytes.Length);
        body.WriteUInt16(57);              // StructureSize
        body.WriteByte(0);                 // SecurityFlags
        body.WriteByte(requestedOplockLevel); // RequestedOplockLevel
        body.WriteUInt32(2);               // ImpersonationLevel = Impersonation
        body.WriteUInt64(0);               // SmbCreateFlags
        body.WriteUInt64(0);               // Reserved
        body.WriteUInt32(desiredAccess);
        body.WriteUInt32(0);               // FileAttributes
        body.WriteUInt32(shareAccess);     // ShareAccess (default READ|WRITE|DELETE)
        body.WriteUInt32(disposition);
        body.WriteUInt32(options);
        int nameOffPos = body.Position;
        body.WriteUInt16(0);               // NameOffset (patch)
        body.WriteUInt16((ushort)nameBytes.Length);
        int ctxOffPos = body.Position;
        body.WriteUInt32(0);               // CreateContextsOffset (patch)
        body.WriteUInt32(0);               // CreateContextsLength (patch)
        int nameStart = body.Position;
        if (nameBytes.Length > 0) body.WriteBytes(nameBytes);
        else body.WriteByte(0);            // StructureSize "+1"
        body.PatchUInt16(nameOffPos, (ushort)(Smb2Header.Size + nameStart));

        if (createContexts is { Length: > 0 })
        {
            PadToAbs8(body);               // contexts are 8-byte aligned (relative to message start)
            int ctxStart = body.Position;
            body.WriteBytes(createContexts);
            body.PatchUInt32(ctxOffPos, (uint)(Smb2Header.Size + ctxStart));
            body.PatchUInt32(ctxOffPos + 4, (uint)createContexts.Length);
        }

        byte[] header = BuildHeader(SmbCommand.Create, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    /// <summary>Builds a single "RqLs" lease-V1 CREATE context blob (32-byte data) as an 8-byte-aligned chain.</summary>
    public static byte[] BuildLeaseV1Context(byte[] leaseKey16, LeaseState requestedState)
    {
        var data = new byte[LeaseRequest.V1Size];
        var w = new SpanWriter(data);
        w.WriteBytes(leaseKey16);
        w.WriteUInt32((uint)requestedState);
        w.WriteUInt32(0);                  // LeaseFlags
        w.WriteUInt64(0);                  // LeaseDuration
        return CreateContextList.Serialize(new[]
        {
            new CreateContext { Name = LeaseContextName(), Data = data },
        });
    }

    /// <summary>
    /// Builds a single "RqLs" lease-V2 CREATE context blob (52-byte data, directory-lease capable,
    /// §2.2.13.2.10) as an 8-byte-aligned chain. When <paramref name="parentKey16"/> is provided the
    /// <c>ParentLeaseKeySet</c> flag is set and the key written into the ParentLeaseKey field.
    /// </summary>
    public static byte[] BuildLeaseV2Context(byte[] leaseKey16, LeaseState requestedState,
        byte[]? parentKey16 = null, ushort epoch = 0)
    {
        var data = new byte[LeaseRequest.V2Size];
        var w = new SpanWriter(data);
        w.WriteBytes(leaseKey16);
        w.WriteUInt32((uint)requestedState);
        w.WriteUInt32((uint)(parentKey16 is not null ? LeaseFlags.ParentLeaseKeySet : LeaseFlags.None));
        w.WriteUInt64(0);                  // LeaseDuration
        w.WriteBytes(parentKey16 ?? new byte[16]);
        w.WriteUInt16(epoch);
        w.WriteUInt16(0);                  // Reserved
        return CreateContextList.Serialize(new[]
        {
            new CreateContext { Name = LeaseContextName(), Data = data },
        });
    }

    /// <summary>Builds a LEASE_BREAK acknowledgment (client→server, §2.2.24.2, StructureSize 36).</summary>
    public static byte[] BuildLeaseBreakAck(ulong messageId, ulong sessionId, uint treeId,
        byte[] leaseKey16, LeaseState state, byte[]? signingKey = null,
        SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(36);
        body.WriteUInt16(36);              // StructureSize
        body.WriteUInt16(0);               // Reserved
        body.WriteUInt32(0);               // Flags
        body.WriteBytes(leaseKey16);
        body.WriteUInt32((uint)state);
        body.WriteUInt64(0);               // LeaseDuration

        byte[] header = BuildHeader(SmbCommand.OplockBreak, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    private static byte[] LeaseContextName()
    {
        var b = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(b, CreateContextNames.Lease);
        return b;
    }

    public static byte[] BuildQueryDirectoryRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, byte infoClass, string pattern, uint outputBufferLength,
        byte flags = 0, byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        byte[] patternBytes = System.Text.Encoding.Unicode.GetBytes(pattern);
        var body = new GrowableWriter(40 + patternBytes.Length);
        body.WriteUInt16(33);              // StructureSize
        body.WriteByte(infoClass);
        body.WriteByte(flags);
        body.WriteUInt32(0);               // FileIndex
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);
        int nameOffPos = body.Position;
        body.WriteUInt16(0);               // FileNameOffset (patch)
        body.WriteUInt16((ushort)patternBytes.Length);
        body.WriteUInt32(outputBufferLength);
        int nameStart = body.Position;
        if (patternBytes.Length > 0) body.WriteBytes(patternBytes);
        body.PatchUInt16(nameOffPos, (ushort)(patternBytes.Length > 0 ? Smb2Header.Size + nameStart : 0));

        byte[] header = BuildHeader(SmbCommand.QueryDirectory, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    public static byte[] BuildReadRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, uint length, ulong offset,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(50);
        body.WriteUInt16(49);              // StructureSize
        body.WriteByte(0);                 // Padding
        body.WriteByte(0);                 // Flags
        body.WriteUInt32(length);
        body.WriteUInt64(offset);
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);
        body.WriteUInt32(0);               // MinimumCount
        body.WriteUInt32(0);               // Channel
        body.WriteUInt32(0);               // RemainingBytes
        body.WriteUInt16(0);               // ReadChannelInfoOffset
        body.WriteUInt16(0);               // ReadChannelInfoLength
        body.WriteByte(0);                 // Buffer (StructureSize "+1")

        byte[] header = BuildHeader(SmbCommand.Read, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    public static byte[] BuildCloseRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, byte[]? signingKey = null,
        SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(24);
        body.WriteUInt16(24);              // StructureSize
        body.WriteUInt16(0);               // Flags
        body.WriteUInt32(0);               // Reserved
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);

        byte[] header = BuildHeader(SmbCommand.Close, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    public static byte[] BuildWriteRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, ulong offset, byte[] data,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(48 + data.Length);
        body.WriteUInt16(49);              // StructureSize
        int dataOffPos = body.Position;
        body.WriteUInt16(0);               // DataOffset (patch)
        body.WriteUInt32((uint)data.Length);
        body.WriteUInt64(offset);
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);
        body.WriteUInt32(0);               // Channel
        body.WriteUInt32(0);               // RemainingBytes
        body.WriteUInt16(0);               // WriteChannelInfoOffset
        body.WriteUInt16(0);               // WriteChannelInfoLength
        body.WriteUInt32(0);               // Flags
        int dataStart = body.Position;
        body.WriteBytes(data);
        body.PatchUInt16(dataOffPos, (ushort)(Smb2Header.Size + dataStart));

        byte[] header = BuildHeader(SmbCommand.Write, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    public static byte[] BuildQueryInfoRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, byte infoType, byte fileInfoClass, uint outputBufferLength,
        uint additionalInformation = 0, byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(40);
        body.WriteUInt16(41);              // StructureSize
        body.WriteByte(infoType);
        body.WriteByte(fileInfoClass);
        body.WriteUInt32(outputBufferLength);
        body.WriteUInt16(0);               // InputBufferOffset
        body.WriteUInt16(0);               // Reserved
        body.WriteUInt32(0);               // InputBufferLength
        body.WriteUInt32(additionalInformation);
        body.WriteUInt32(0);               // Flags
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);

        byte[] header = BuildHeader(SmbCommand.QueryInfo, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    public static byte[] BuildSetInfoRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, byte infoType, byte fileInfoClass, byte[] buffer,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac,
        uint additionalInformation = 0)
    {
        var body = new GrowableWriter(40 + buffer.Length);
        body.WriteUInt16(33);              // StructureSize
        body.WriteByte(infoType);
        body.WriteByte(fileInfoClass);
        body.WriteUInt32((uint)buffer.Length);
        int offPos = body.Position;
        body.WriteUInt16(0);               // BufferOffset (patch)
        body.WriteUInt16(0);               // Reserved
        body.WriteUInt32(additionalInformation); // AdditionalInformation (SECURITY_INFORMATION for InfoType Security)
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);
        int bufStart = body.Position;
        body.WriteBytes(buffer);
        body.PatchUInt16(offPos, (ushort)(Smb2Header.Size + bufStart));

        byte[] header = BuildHeader(SmbCommand.SetInfo, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    public static byte[] BuildIoctlRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, uint ctlCode, byte[] input,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(56 + input.Length);
        body.WriteUInt16(57);              // StructureSize
        body.WriteUInt16(0);               // Reserved
        body.WriteUInt32(ctlCode);
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);
        int inOffPos = body.Position;
        body.WriteUInt32(0);               // InputOffset (patch)
        body.WriteUInt32((uint)input.Length);
        body.WriteUInt32(0);               // MaxInputResponse
        body.WriteUInt32(0);               // OutputOffset
        body.WriteUInt32(0);               // OutputCount
        body.WriteUInt32(65536);           // MaxOutputResponse
        body.WriteUInt32(1);               // Flags = IS_FSCTL
        body.WriteUInt32(0);               // Reserved2
        int inStart = body.Position;
        body.WriteBytes(input);
        body.PatchUInt32(inOffPos, (uint)(input.Length > 0 ? Smb2Header.Size + inStart : 0));

        byte[] header = BuildHeader(SmbCommand.Ioctl, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    /// <summary>Baut einen LOCK-Request mit beliebig vielen Lock-/Unlock-Elementen.</summary>
    public static byte[] BuildLockRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, (ulong Offset, ulong Length, uint Flags)[] locks,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(24 + locks.Length * 24);
        body.WriteUInt16(48);                      // StructureSize
        body.WriteUInt16((ushort)locks.Length);    // LockCount
        body.WriteUInt32(0);                       // LockSequenceNumber/Index
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);
        foreach ((ulong Offset, ulong Length, uint Flags) l in locks)
        {
            body.WriteUInt64(l.Offset);
            body.WriteUInt64(l.Length);
            body.WriteUInt32(l.Flags);
            body.WriteUInt32(0);                   // Reserved
        }

        byte[] header = BuildHeader(SmbCommand.Lock, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    /// <summary>Builds a CHANGE_NOTIFY request for a directory handle.</summary>
    public static byte[] BuildChangeNotifyRequest(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, uint completionFilter, ushort flags = 0,
        uint outputBufferLength = 65536, byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(32);
        body.WriteUInt16(32);              // StructureSize
        body.WriteUInt16(flags);
        body.WriteUInt32(outputBufferLength);
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);
        body.WriteUInt32(completionFilter);
        body.WriteUInt32(0);               // Reserved

        byte[] header = BuildHeader(SmbCommand.ChangeNotify, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    /// <summary>Baut ein OPLOCK_BREAK Acknowledgment (Client→Server, §2.2.24.1).</summary>
    public static byte[] BuildOplockBreakAck(ulong messageId, ulong sessionId, uint treeId,
        ulong persistentId, ulong volatileId, byte oplockLevel,
        byte[]? signingKey = null, SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac)
    {
        var body = new GrowableWriter(24);
        body.WriteUInt16(24);              // StructureSize
        body.WriteByte(oplockLevel);
        body.WriteByte(0);                 // Reserved
        body.WriteUInt32(0);               // Reserved2
        body.WriteUInt64(persistentId);
        body.WriteUInt64(volatileId);

        byte[] header = BuildHeader(SmbCommand.OplockBreak, messageId, sessionId, treeId);
        return Finish(header, body.ToArray(), messageId, signingKey, alg);
    }

    private static byte[] Finish(byte[] header, byte[] body, ulong messageId, byte[]? signingKey, SmbSigningAlgorithmId alg)
    {
        byte[] message = Concat(header, body);
        if (signingKey is not null) SignInPlace(message, messageId, signingKey, alg);
        return message;
    }

    private static void SignInPlace(byte[] message, ulong messageId, byte[] signingKey, SmbSigningAlgorithmId alg)
    {
        // SMB2_FLAGS_SIGNED setzen (Offset 16).
        uint flags = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(16, 4));
        flags |= (uint)Smb2HeaderFlags.Signed;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(16, 4), flags);
        Smb.Crypto.Smb2Signer.SignInPlace(alg, signingKey, message, messageId, isServer: false, isCancel: false);
    }

    private static void PadToAbs8(GrowableWriter w)
    {
        int abs = Smb2Header.Size + w.Position;
        int pad = (8 - (abs % 8)) % 8;
        if (pad > 0) w.WriteZeros(pad);
    }

    public static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }

    public static bool IsSmb2(ReadOnlySpan<byte> data) => SmbProtocolIds.IsSmb2(data);
}
