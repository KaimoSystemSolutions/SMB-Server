using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Server.Oplocks;
using Smb.Server.Rpc;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Datei-Commands (M4, Context §13–§16): CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY,
/// QUERY_INFO über ein <see cref="IFileStore"/>-Backend. Read-Only-Browse funktioniert
/// vollständig; Schreiben je nach Backend-Konfiguration.
/// </summary>
public sealed partial class Smb2Dispatcher
{
    // Access-Mask-Bits (Context §13.1).
    private const uint FileReadData = 0x00000001, FileWriteData = 0x00000002, FileAppendData = 0x00000004;
    private const uint Delete = 0x00010000, GenericRead = 0x80000000, GenericWrite = 0x40000000;
    private const uint GenericAll = 0x10000000, MaximumAllowed = 0x02000000;

    private bool TryGetFileStore(SmbSession session, uint treeId, out IFileStore store, out NtStatus error)
    {
        store = null!;
        error = NtStatus.Success;
        if (!session.TreeConnects.TryGetValue(treeId, out SmbTreeConnect? tree))
        {
            error = NtStatus.NetworkNameDeleted;
            return false;
        }
        if (tree.Share.FileStore is null)
        {
            error = NtStatus.NotSupported; // z.B. IPC$ ohne Datei-Backend
            return false;
        }
        store = tree.Share.FileStore;
        return true;
    }

    private bool TryGetOpen(SmbSession session, ulong persistent, ulong volatileId, out SmbOpen open)
        => session.Opens.TryGetValue((persistent, volatileId), out open!);

    private ResponseSegment HandleCreate(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);
        if (!session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree))
            return BuildError(header, NtStatus.NetworkNameDeleted);

        // Named-Pipe-Share (IPC$): DCERPC-Pipe öffnen statt Datei-Backend.
        if (tree.Share.Type == ShareType.Pipe)
            return HandlePipeCreate(connection, header, session, tree, segment);

        if (tree.Share.FileStore is not { } store)
            return BuildError(header, NtStatus.NotSupported);

        CreateRequest request = CreateRequest.Parse(segment, Smb2Header.Size);

        // [AUDIT-2026-06] DesiredAccess gegen die von der Autorisierungs-Policy gewährte MaximalAccess
        // durchsetzen (§3.3.5.9). Zuvor wurde DesiredAccess ungefiltert gewährt → eine Policy mit
        // reduzierten Rechten (z.B. ReadOnly pro User/Gruppe) war für Datei-Operationen wirkungslos;
        // nur das globale readOnly-Flag des FileStore begrenzte. MAXIMUM_ALLOWED gewährt genau die
        // erlaubte Maske. Vergleich auf Intent-Ebene (Read/Write/Delete), um Generic-Bits korrekt zu
        // behandeln. Siehe docs/SECURITY_AUDIT.md (Finding H3).
        FileAccessIntent allowedIntent = MapAccess(tree.MaximalAccess);
        bool maximumAllowed = (request.DesiredAccess & MaximumAllowed) != 0;
        FileAccessIntent access = maximumAllowed ? allowedIntent : MapAccess(request.DesiredAccess);
        if (!maximumAllowed && (access & ~allowedIntent) != 0)
            return BuildError(header, NtStatus.AccessDenied);
        uint grantedAccess = maximumAllowed ? tree.MaximalAccess : request.DesiredAccess;

        var disposition = (CreateDispositionIntent)(uint)request.Disposition;
        bool dirRequired = request.Options.HasFlag(CreateOptions.DirectoryFile);
        bool nonDirRequired = request.Options.HasFlag(CreateOptions.NonDirectoryFile);

        FileStoreResult<IFileHandle> result = store.Create(
            request.Name, access, disposition, dirRequired, nonDirRequired, out CreateOutcome outcome);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);

        IFileHandle handle = result.Value!;
        if (request.Options.HasFlag(CreateOptions.DeleteOnClose))
            store.SetDeleteOnClose(handle, true);

        ulong volatileId = connection.AllocateFileId();
        var open = new SmbOpen
        {
            PersistentFileId = 0,
            VolatileFileId = volatileId,
            Session = session,
            TreeConnect = tree,
            LocalOpen = handle,
            GrantedAccess = grantedAccess,
            PathName = request.Name,
        };
        session.Opens[open.Key] = open;
        Interlocked.Increment(ref tree.OpenCount);

        // Oplock anfordern (Context §15): Der Manager bestimmt das gewährte Level und liefert die
        // durch diesen Open fälligen Breaks an andere Halter, die out-of-band benachrichtigt werden.
        OplockGrant grant = _server.Options.OplockManager.RequestOplock(open, request.RequestedOplockLevel);
        open.OplockLevel = grant.GrantedLevel;
        DispatchOplockBreaks(grant.Breaks);

        FileEntryInfo info = handle.GetInfo();
        var response = new CreateResponse
        {
            OplockLevel = grant.GrantedLevel,
            CreateAction = (CreateAction)(uint)outcome,
            CreationTime = info.CreationTime,
            LastAccessTime = info.LastAccessTime,
            LastWriteTime = info.LastWriteTime,
            ChangeTime = info.ChangeTime,
            AllocationSize = info.AllocationSize,
            EndOfFile = info.EndOfFile,
            FileAttributes = (uint)info.Attributes,
            PersistentFileId = open.PersistentFileId,
            VolatileFileId = open.VolatileFileId,
        };

        return MaybeSigned(session, RespHeader(header, session), response.ToBody());
    }

    private ResponseSegment HandlePipeCreate(SmbConnection connection, Smb2Header header,
        SmbSession session, SmbTreeConnect tree, ReadOnlySpan<byte> segment)
    {
        CreateRequest request = CreateRequest.Parse(segment, Smb2Header.Size);
        string pipeName = request.Name.TrimStart('\\');

        // Aktuell nur srvsvc (Share-Enumeration). Andere Pipes → nicht gefunden.
        if (!pipeName.Equals("srvsvc", StringComparison.OrdinalIgnoreCase))
            return BuildError(header, NtStatus.ObjectNameNotFound);

        // Sichtbare Shares (über die Autorisierungs-Policy gefiltert) als Enumerationsquelle.
        var entries = new List<ShareEntry>();
        foreach (IShare share in _server.GetVisibleShares(session.Identity ?? AnonymousIdentity, connection))
            entries.Add(new ShareEntry(share.Name, SrvsvcEndpoint.MapStype(share.Type), share.Remark));

        var pipe = new RpcPipe(new SrvsvcEndpoint(entries));

        ulong volatileId = connection.AllocateFileId();
        var open = new SmbOpen
        {
            PersistentFileId = 0,
            VolatileFileId = volatileId,
            Session = session,
            TreeConnect = tree,
            Pipe = pipe,
            GrantedAccess = request.DesiredAccess,
            PathName = pipeName,
        };
        session.Opens[open.Key] = open;

        var response = new CreateResponse
        {
            OplockLevel = OplockLevel.None,
            CreateAction = CreateAction.Opened,
            FileAttributes = (uint)SmbFileAttributes.Normal,
            PersistentFileId = open.PersistentFileId,
            VolatileFileId = open.VolatileFileId,
        };
        return MaybeSigned(session, RespHeader(header, session), response.ToBody());
    }

    private ResponseSegment HandleIoctl(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        IoctlMessage.Request req = IoctlMessage.ParseRequest(segment, Smb2Header.Size);

        // FSCTL_PIPE_TRANSCEIVE: DCERPC-Request → Response über die Named Pipe.
        if (req.CtlCode == IoctlMessage.FsctlPipeTransceive
            && TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open)
            && open.Pipe is { } pipe)
        {
            byte[] output = pipe.Transceive(req.Input);
            return MaybeSigned(session, RespHeader(header, session),
                IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
        }

        // FSCTL_SRV_ENUMERATE_SNAPSHOTS: „Vorherige Versionen" eines versionierten Shares auflisten.
        if (req.CtlCode == IoctlMessage.FsctlSrvEnumerateSnapshots)
            return HandleEnumerateSnapshots(header, session, req);

        return BuildError(header, NtStatus.InvalidDeviceRequest);
    }

    /// <summary>
    /// Beantwortet FSCTL_SRV_ENUMERATE_SNAPSHOTS, wenn das Share-Backend Snapshots vorhält
    /// (<see cref="ISnapshotStore"/>). Der Pfad des offenen Handles bestimmt, für welche Datei
    /// (bzw. bei der Wurzel: für alle Dateien) die <c>@GMT-…</c>-Token geliefert werden.
    /// </summary>
    private ResponseSegment HandleEnumerateSnapshots(Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        if (!session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree)
            || tree.Share.FileStore is not ISnapshotStore snapshots)
            return BuildError(header, NtStatus.InvalidDeviceRequest);

        string path = TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open)
            ? open.PathName
            : string.Empty;

        IReadOnlyList<DateTime> times = snapshots.GetSnapshots(path);
        var tokens = new List<string>(times.Count);
        foreach (DateTime t in times)
            tokens.Add(GmtToken.Format(t));

        byte[] output = IoctlMessage.BuildEnumerateSnapshotsResponse(tokens, req.MaxOutputResponse);
        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
    }

    private ResponseSegment HandleClose(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        (ushort flags, ulong persistent, ulong vol) = CloseMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, persistent, vol, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        FileEntryInfo? info = (flags & CloseMessage.FlagPostQueryAttributes) != 0 ? open.LocalOpen?.GetInfo() : null;
        session.Opens.TryRemove(open.Key, out _);
        ReleaseLocks(connection, open);
        _server.Options.OplockManager.ReleaseOwner(open);
        open.LocalOpen?.Dispose();

        byte[] body = info is null
            ? CloseMessage.BuildResponseBody()
            : CloseMessage.BuildResponseBody(true,
                new FileTimes(info.CreationTime, info.LastAccessTime, info.LastWriteTime, info.ChangeTime),
                info.AllocationSize, info.EndOfFile, (uint)info.Attributes);

        return MaybeSigned(session, RespHeader(header, session), body);
    }

    private ResponseSegment HandleRead(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        ReadMessage.Request req = ReadMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        // Named-Pipe-READ: liefert die gepufferte DCERPC-Antwort (Write→Read-Muster).
        if (open.Pipe is { } pipe)
            return MaybeSigned(session, RespHeader(header, session), ReadMessage.BuildResponseBody(pipe.TakeOutput()));

        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err) || open.LocalOpen is null)
            return BuildError(header, err == NtStatus.Success ? NtStatus.FileClosed : err);

        uint length = Math.Min(req.Length, connection.MaxReadSize);
        if (!_server.Options.LockManager.IsRangeAccessible(open, req.Offset, length, forWrite: false))
            return BuildError(header, NtStatus.FileLockConflict);
        var buffer = new byte[length];
        FileStoreResult<int> result = store.Read(open.LocalOpen, (long)req.Offset, buffer);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);
        if (result.Value == 0 && length > 0)
            return BuildError(header, NtStatus.EndOfFile);

        return MaybeSigned(session, RespHeader(header, session),
            ReadMessage.BuildResponseBody(buffer.AsSpan(0, result.Value)));
    }

    private ResponseSegment HandleWrite(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        WriteMessage.Request req = WriteMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        // Named-Pipe-WRITE: DCERPC-Request verarbeiten, Antwort puffern (für nachfolgendes READ).
        if (open.Pipe is { } pipe)
        {
            pipe.Transceive(req.Data);
            return MaybeSigned(session, RespHeader(header, session), WriteMessage.BuildResponseBody((uint)req.Data.Length));
        }

        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err) || open.LocalOpen is null)
            return BuildError(header, err == NtStatus.Success ? NtStatus.FileClosed : err);

        if (!_server.Options.LockManager.IsRangeAccessible(open, req.Offset, (ulong)req.Data.Length, forWrite: true))
            return BuildError(header, NtStatus.FileLockConflict);

        FileStoreResult<int> result = store.Write(open.LocalOpen, (long)req.Offset, req.Data);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);

        return MaybeSigned(session, RespHeader(header, session),
            WriteMessage.BuildResponseBody((uint)result.Value));
    }

    private ResponseSegment HandleQueryDirectory(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        QueryDirectoryMessage.Request req = QueryDirectoryMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        if ((req.Flags & QueryDirectoryMessage.FlagRestartScan) != 0)
            open.DirectoryEnumStarted = false;

        // Zweite Abfrage ohne Restart → Ende (Context §14).
        if (open.DirectoryEnumStarted)
            return BuildError(header, NtStatus.NoMoreFiles);

        FileStoreResult<IReadOnlyList<FileEntryInfo>> listing = store.QueryDirectory(open.LocalOpen, req.SearchPattern);
        if (!listing.IsSuccess)
            return BuildError(header, listing.Status);

        IReadOnlyList<FileEntryInfo> entries = listing.Value!;
        if (entries.Count == 0)
            return BuildError(header, NtStatus.NoSuchFile);

        var stats = new List<FsccFileStat>(entries.Count);
        foreach (FileEntryInfo e in entries)
            stats.Add(ToStat(e, (ulong)(uint)e.Name.GetHashCode()));

        byte[] buffer = FsccStructures.BuildDirectoryListing(stats, req.InfoClass);
        if (buffer.Length > req.OutputBufferLength)
            return BuildError(header, NtStatus.InvalidParameter); // Puffer zu klein (vereinfachte Phase-1-Variante)

        open.DirectoryEnumStarted = true;
        return MaybeSigned(session, RespHeader(header, session), QueryDirectoryMessage.BuildResponseBody(buffer));
    }

    private ResponseSegment HandleQueryInfo(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        QueryInfoMessage.Request req = QueryInfoMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        FsccFileStat stat = ToStat(open.LocalOpen.GetInfo(), open.VolatileFileId);

        byte[]? buffer = req.InfoType switch
        {
            InfoType.File => FsccStructures.BuildFileInformation(stat, (FileInformationClass)req.FileInfoClass),
            InfoType.FileSystem => FsccStructures.BuildFileSystemInformation(
                (FsInformationClass)req.FileInfoClass, "SHARE", 0x12345678),
            _ => null,
        };

        if (buffer is null)
            return BuildError(header, NtStatus.InvalidInfoClass);

        return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(buffer));
    }

    private ResponseSegment HandleSetInfo(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        SetInfoMessage.Request req = SetInfoMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        if (req.InfoType != InfoType.File)
            return BuildError(header, NtStatus.NotSupported);

        NtStatus status = (FileInformationClass)req.FileInfoClass switch
        {
            FileInformationClass.FileEndOfFileInformation =>
                store.SetEndOfFile(open.LocalOpen, System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(req.Buffer)),
            FileInformationClass.FileDispositionInformation =>
                store.SetDeleteOnClose(open.LocalOpen, req.Buffer.Length > 0 && req.Buffer[0] != 0),
            FileInformationClass.FileRenameInformation => DoRename(store, open.LocalOpen, req.Buffer),
            // Zeiten/Attribute/Allocation akzeptieren wir (kein hartes Setzen nötig fürs Browsen/Schreiben).
            FileInformationClass.FileBasicInformation => NtStatus.Success,
            FileInformationClass.FileAllocationInformation => NtStatus.Success,
            FileInformationClass.FilePositionInformation => NtStatus.Success,
            _ => NtStatus.InvalidInfoClass,
        };

        if (status != NtStatus.Success)
            return BuildError(header, status);

        return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
    }

    private static NtStatus DoRename(IFileStore store, IFileHandle handle, byte[] buffer)
    {
        (bool replace, string newPath) = SetInfoMessage.ParseRename(buffer);
        return store.Rename(handle, newPath, replace);
    }

    private ResponseSegment HandleFlush(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        // FLUSH Request (§2.2.17): StructureSize(2)+Reserved1(2)+Reserved2(4)+FileId(16).
        ulong persistent = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(segment.Slice(Smb2Header.Size + 8, 8));
        ulong vol = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(segment.Slice(Smb2Header.Size + 16, 8));
        if (TryGetOpen(session, persistent, vol, out SmbOpen open) && open.LocalOpen is not null
            && TryGetFileStore(session, header.TreeId, out IFileStore store, out _))
            store.Flush(open.LocalOpen);

        // FLUSH Response (§2.2.18): StructureSize=4, Reserved(2).
        var body = new byte[4];
        new Smb.Protocol.Wire.SpanWriter(body).WriteUInt16(4);
        return MaybeSigned(session, RespHeader(header, session), body);
    }

    // --- Hilfsfunktionen ---

    private Smb2Header RespHeader(Smb2Header request, SmbSession session)
    {
        Smb2Header h = request.CreateResponse(NtStatus.Success);
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = CreditManager.ComputeCreditGrant(request.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return h;
    }

    private static FileAccessIntent MapAccess(uint desiredAccess)
    {
        FileAccessIntent intent = FileAccessIntent.None;
        if ((desiredAccess & (FileReadData | GenericRead | GenericAll | MaximumAllowed)) != 0)
            intent |= FileAccessIntent.Read;
        if ((desiredAccess & (FileWriteData | FileAppendData | GenericWrite | GenericAll)) != 0)
            intent |= FileAccessIntent.Write;
        if ((desiredAccess & (Delete | GenericAll)) != 0)
            intent |= FileAccessIntent.Delete;
        return intent;
    }

    private static FsccFileStat ToStat(FileEntryInfo info, ulong indexNumber) => new()
    {
        Name = info.Name,
        FileAttributes = (uint)info.Attributes,
        EndOfFile = info.EndOfFile,
        AllocationSize = info.AllocationSize,
        CreationTime = info.CreationTime,
        LastAccessTime = info.LastAccessTime,
        LastWriteTime = info.LastWriteTime,
        ChangeTime = info.ChangeTime,
        IsDirectory = info.IsDirectory,
        IndexNumber = (long)indexNumber,
    };
}
