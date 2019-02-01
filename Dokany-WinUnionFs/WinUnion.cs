using DokanNet;
using DokanNet.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Runtime.Caching;
using FileAccess = DokanNet.FileAccess;

namespace Dokany_WinUnionFs
{
    class WinUnion : IDokanOperations
    {
        private const FileAccess DataAccess = FileAccess.ReadData | FileAccess.WriteData | FileAccess.AppendData |
                                              FileAccess.Execute |
                                              FileAccess.GenericExecute | FileAccess.GenericWrite |
                                              FileAccess.GenericRead;

        private const FileAccess DataWriteAccess = FileAccess.WriteData | FileAccess.AppendData |
                                                   FileAccess.Delete |
                                                   FileAccess.GenericWrite;
        //private String path;
        private List<FS> fsl;
        MemoryCache mc = MemoryCache.Default;
        private CacheItemPolicy cip = new CacheItemPolicy();
        private ConsoleLogger logger = new ConsoleLogger("[Union] ");
        private FS default_FS_RW;
        public WinUnion(List<FS> fses) {
            this.fsl = fses;
            cip.SlidingExpiration.Add(new TimeSpan(0,0,30));
        }

        public WinUnion()
        {
        }

        public FS GetOrAdd(string fileName, Func<FS> builder)
        {
            if(mc.Contains(fileName))
            {
                return (FS)mc[fileName];
            }
            else
            {
                FS tmp = builder();
                mc.Add(fileName, tmp, cip);
                return tmp;
            }
        }
        protected void Invalidate(string fileName)
        {
            if(mc.Contains(fileName))
            {
#if TRACE
                logger.Debug("CACHE : INVALIDATING : " + fileName);
#endif
                mc.Remove(fileName);
            }
        }
        protected String combine(String path1, string path2)
        {
            if(path2.Substring(1) != "")
            {
                return Path.Combine(path1, path2.Substring(1));
            }
            return path1;
        }
        protected FS GetFSWith(string fileName)
        {
            var res = fsl.Where(FS => (Directory.Exists(combine(FS.TLD, fileName)) || File.Exists(combine(FS.TLD, fileName))));
            return res.Count() != 0 ? res.First() : fsl.Where(FS => FS.P == RWPerm.RW).First();
            
        }
        protected string GetPath(string fileName)
        {

            FS fs = GetOrAdd(fileName, () => GetFSWith(fileName));
            //FS fs = getFSWith(fileName);
            return combine(fs.TLD, fileName);
        }
        protected string GetPath_RW(string fileName)
        {
            FS fs_o = GetOrAdd(fileName, () => GetFSWith(fileName));
            //FS fs = getFSWith(fileName);
            if (fs_o.P == RWPerm.RO)
            {
                return combine(fsl.Where(FS => FS.P == RWPerm.RW).First().TLD, fileName);
            }
            else
            {
                return combine(fs_o.TLD, fileName);
            }
        }

#region Implementation of IDokanOperations

        public NtStatus CreateFile(string fileName, FileAccess access, FileShare share, FileMode mode,
            FileOptions options, FileAttributes attributes, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("CreateFile : " + fileName);
#endif
            var result = DokanResult.Success;
            var FS = GetOrAdd(fileName, () => GetFSWith(fileName));
            string filePath = combine(FS.TLD, fileName);
            if(FS.P == RWPerm.RO && !((access & DataWriteAccess) == 0))
            {
                string filePath_RW = GetPath_RW(fileName);
                if (!File.Exists(filePath_RW) && !info.IsDirectory) 
                {
                    Invalidate(fileName);
                    File.Copy(filePath, filePath_RW);
                    filePath = filePath_RW;
                }
            }
            if (info.IsDirectory)
            {
                try
                {
                    switch (mode)
                    {
                        case FileMode.Open:
                            if (!Directory.Exists(filePath))
                            {
                                try
                                {
                                    if (!File.GetAttributes(filePath).HasFlag(FileAttributes.Directory))
                                        return DokanResult.NotADirectory;
                                }
                                catch (Exception)
                                {
                                    return DokanResult.FileNotFound;
                                }
                                return DokanResult.PathNotFound;
                            }

                            new DirectoryInfo(filePath).EnumerateFileSystemInfos().Any();
                            // you can't list the directory
                            break;

                        case FileMode.CreateNew:
                            if (Directory.Exists(filePath))
                                return DokanResult.FileExists;
                            try
                            {
                                File.GetAttributes(filePath).HasFlag(FileAttributes.Directory);
                                return DokanResult.AlreadyExists;
                            }
                            catch (IOException)
                            {
                            }

                            Directory.CreateDirectory(filePath);
                            break;
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    return DokanResult.AccessDenied;
                }
            }
            else
            {
                var pathExists = true;
                var pathIsDirectory = false;

                var readWriteAttributes = (access & DataAccess) == 0;
                var readAccess = (access & DataWriteAccess) == 0;
                try
                {
                    pathExists = (Directory.Exists(filePath) || File.Exists(filePath));
                    pathIsDirectory = File.GetAttributes(filePath).HasFlag(FileAttributes.Directory);
                }
                catch (IOException)
                {
                }
                switch (mode)
                {
                    case FileMode.Open:
#if TRACE
                        logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode);
#endif
                        if (pathExists)
                        {
                            // check if driver only wants to read attributes, security info, or open directory
                            if (readWriteAttributes || pathIsDirectory)
                            {
                                if (pathIsDirectory && (access & FileAccess.Delete) == FileAccess.Delete
                                    && (access & FileAccess.Synchronize) != FileAccess.Synchronize)
                                {
                                    //It is a DeleteFile request on a directory
#if TRACE
                                    logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + DokanResult.AccessDenied);
#endif
                                    return DokanResult.AccessDenied;
                                }

                                info.IsDirectory = pathIsDirectory;
                                info.Context = new object();
                                // must set it to someting if you return DokanError.Success
                                return DokanResult.Success;
                            }
                        }
                        else
                        {
#if TRACE
                            logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + DokanResult.FileNotFound);
#endif
                            return DokanResult.FileNotFound;
                        }
                        break;
                    case FileMode.CreateNew:
                        if (pathExists)
                        {
#if TRACE
                            logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + DokanResult.FileExists);
#endif
                            return DokanResult.FileExists;
                        }
                        break;
                        
                    case FileMode.Truncate:
                        if (!pathExists)
                        {
#if TRACE
                            logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + DokanResult.FileNotFound);
#endif
                            return DokanResult.FileNotFound;
                        }
                        break;
                }

                try
                {
                    info.Context = new FileStream(filePath, mode,
                        readAccess ? System.IO.FileAccess.Read : System.IO.FileAccess.ReadWrite, share, 4096, options);

                    if (pathExists && (mode == FileMode.OpenOrCreate
                                       || mode == FileMode.Create))
                        result = DokanResult.AlreadyExists;

                    if (mode == FileMode.CreateNew || mode == FileMode.Create) //Files are always created as Archive
                        attributes |= FileAttributes.Archive;
                    File.SetAttributes(filePath, attributes);
                }
                catch (UnauthorizedAccessException) // don't have access rights
                {
#if TRACE
                    logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + DokanResult.AccessDenied);
#endif
                    return DokanResult.AccessDenied;
                }
                catch (DirectoryNotFoundException)
                {
#if TRACE
                    logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + DokanResult.PathNotFound);
#endif
                    return DokanResult.PathNotFound;
                }
                catch (Exception ex)
                {
                    var hr = (uint)Marshal.GetHRForException(ex);
                    switch (hr)
                    {
                        case 0x80070020: //Sharing violation
#if TRACE
                            logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + DokanResult.SharingViolation);
#endif
                            return DokanResult.SharingViolation;
                        default:
                            logger.Debug("Unrecoverable Error : "+hr.ToString("X"));
                            throw;
                    }
                }
            }
#if TRACE
            logger.Debug("File : " + fileName + " : " + filePath + " : " + "ACC : " + access + " : " + mode + " : " + result);
#endif
            return result;
        }

        public void Cleanup(string fileName, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("Cleanup : " + fileName);
#endif
            (info.Context as FileStream)?.Dispose();
            info.Context = null;
            if (info.DeleteOnClose)
            {
                var filePath = GetPath(fileName);
                if (info.IsDirectory)
                {
                    Directory.Delete(filePath);
                }
                else
                {
                    File.Delete(filePath);
                }
            }
        }

        public void CloseFile(string fileName, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("CloseFile : " + fileName);
#endif
            (info.Context as FileStream)?.Dispose();
            info.Context = null;
            // could recreate cleanup code here but this is not called sometimes
        }

        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("ReadFile : " + fileName);
#endif
            if (info.Context == null) // memory mapped read
            {

                using (var stream = new FileStream(GetPath(fileName), FileMode.Open, System.IO.FileAccess.Read))
                {
                    stream.Position = offset;
                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                }
            }
            else // normal read
            {
                var stream = info.Context as FileStream;
                lock (stream) //Protect from overlapped read
                {
                    stream.Position = offset;
                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                }
            }
            return DokanResult.Success;
        }

        public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("WriteFile : " + fileName);
#endif
            if (info.Context == null)
            {
                using (var stream = new FileStream(GetPath(fileName), FileMode.Open, System.IO.FileAccess.Write))
                {
                    stream.Position = offset;
                    stream.Write(buffer, 0, buffer.Length);
                    bytesWritten = buffer.Length;
                }
            }
            else
            {
                var stream = info.Context as FileStream;
                lock (stream) //Protect from overlapped write
                {
                    stream.Position = offset;
                    stream.Write(buffer, 0, buffer.Length);
                }
                bytesWritten = buffer.Length;
            }
            return DokanResult.Success;
        }

        public NtStatus FlushFileBuffers(string fileName, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("FlushFileInfo : " + fileName);
#endif
            try
            {
                ((FileStream)(info.Context)).Flush();
                return DokanResult.Success;
            }
            catch (IOException)
            {
                return DokanResult.DiskFull;
            }
        }

        public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("GetFileInfo : " + fileName);
#endif
            // may be called with info.Context == null, but usually it isn't
            var filePath = GetPath(fileName);
            FileSystemInfo finfo = new FileInfo(filePath);
            if (!finfo.Exists)
                finfo = new DirectoryInfo(filePath);

            fileInfo = new FileInformation
            {
                FileName = fileName,
                Attributes = finfo.Attributes,
                CreationTime = finfo.CreationTime,
                LastAccessTime = finfo.LastAccessTime,
                LastWriteTime = finfo.LastWriteTime,
                Length = (finfo as FileInfo)?.Length ?? 0,
            };
            return DokanResult.Success;
        }

        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, DokanFileInfo info)
        {
            files = FindFilesHelper(fileName, "*");
            return DokanResult.Success;
        }

        public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("SetFileAttributes : " + fileName);
#endif
            try
            {
                if (attributes != 0)

                    File.SetAttributes(GetPath(fileName), attributes);
                return DokanResult.Success;
            }
            catch (UnauthorizedAccessException)
            {
                return DokanResult.AccessDenied;
            }
            catch (FileNotFoundException)
            {
                return DokanResult.FileNotFound;
            }
            catch (DirectoryNotFoundException)
            {
                return DokanResult.PathNotFound;
            }
        }
        public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime,
            DateTime? lastWriteTime, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("SetFileTime : " + fileName);
#endif
            try
            {
                if (info.Context is FileStream stream)
                {
                    var ct = creationTime?.ToFileTime() ?? 0;
                    var lat = lastAccessTime?.ToFileTime() ?? 0;
                    var lwt = lastWriteTime?.ToFileTime() ?? 0;
                    if (NativeMethods.SetFileTime(stream.SafeFileHandle, ref ct, ref lat, ref lwt))
                        return DokanResult.Success;
                    throw Marshal.GetExceptionForHR(Marshal.GetLastWin32Error());
                }

                var filePath = GetPath(fileName);

                if (creationTime.HasValue)
                    File.SetCreationTime(filePath, creationTime.Value);

                if (lastAccessTime.HasValue)
                    File.SetLastAccessTime(filePath, lastAccessTime.Value);

                if (lastWriteTime.HasValue)
                    File.SetLastWriteTime(filePath, lastWriteTime.Value);

                return DokanResult.Success;
            }
            catch (UnauthorizedAccessException)
            {
                return DokanResult.AccessDenied;
            }
            catch (FileNotFoundException)
            {
                return DokanResult.FileNotFound;
            }
        }

        public NtStatus DeleteFile(string fileName, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("DeleteFile : " + fileName);
#endif
            var fs = GetOrAdd(fileName, () => GetFSWith(fileName));
            var filePath = combine(fs.TLD, fileName);
            if (fs.P == RWPerm.RO)
            {
                return DokanResult.AccessDenied;
            }
            else
            {
                filePath = combine(fs.TLD, fileName);
                Invalidate(fileName);
            }
            if (Directory.Exists(filePath))
                return DokanResult.AccessDenied;
            if (!File.Exists(filePath))
                return DokanResult.FileNotFound;
            if (File.GetAttributes(filePath).HasFlag(FileAttributes.Directory))
                return DokanResult.AccessDenied;

            return DokanResult.Success;
            // we just check here if we could delete the file - the true deletion is in Cleanup
        }

        public NtStatus DeleteDirectory(string fileName, DokanFileInfo info)
        {
            return Directory.EnumerateFileSystemEntries(GetPath(fileName)).Any()
                    ? DokanResult.DirectoryNotEmpty
                    : DokanResult.Success;
            // if dir is not empty it can't be deleted
        }

        public NtStatus MoveFile(string oldName, string newName, bool replace, DokanFileInfo info)
        {
            var oldpath = GetPath(oldName);
            var newpath = GetPath_RW(newName);
            var oldpath_RW = GetPath_RW(oldName);
            (info.Context as FileStream)?.Dispose();
            info.Context = null;

            var exist = (info.IsDirectory ? Directory.Exists(newpath) : File.Exists(newpath));
            try
            {

                if (!exist)
                {
                    info.Context = null;
                    if (info.IsDirectory)
                    {
                        if (oldpath_RW.Equals(oldpath))
                        {
                            Directory.Move(oldpath_RW, newpath);
                        }
                        else
                        {
                            if(Directory.Exists(newpath))
                            {
                                Directory.Move(oldpath, newpath);
                            } else
                            {
                                Directory.Move(oldpath, newpath);
                            }
                        }
                    }
                    else
                    {
                        if (oldpath_RW.Equals(oldpath))
                        {
                            File.Move(oldpath_RW, newpath);
                        } else
                        {
                            File.Copy(oldpath, newpath);
                        }
                    }
                    return DokanResult.Success;
                }
                else if (replace)
                {
                    info.Context = null;

                    if (info.IsDirectory) //Cannot replace directory destination - See MOVEFILE_REPLACE_EXISTING
                        return DokanResult.AccessDenied;

                    File.Delete(newpath);
                    File.Move(oldpath, newpath);
                    return DokanResult.Success;
                }
            }
            catch (UnauthorizedAccessException)
            {
                return DokanResult.AccessDenied;
            }
            return DokanResult.FileExists;
        }

        public NtStatus SetEndOfFile(string fileName, long length, DokanFileInfo info)
        {
            try
            {
                ((FileStream)(info.Context)).SetLength(length);
                return DokanResult.Success;
            }
            catch (IOException)
            {
                return DokanResult.DiskFull;
            }
        }

        public NtStatus SetAllocationSize(string fileName, long length, DokanFileInfo info)
        {
            try
            {
                ((FileStream)(info.Context)).SetLength(length);
                return DokanResult.Success;
            }
            catch (IOException)
            {
                return DokanResult.DiskFull;
            }
        }

        public NtStatus LockFile(string fileName, long offset, long length, DokanFileInfo info)
        {
            try
            {
                ((FileStream)(info.Context)).Lock(offset, length);
                return DokanResult.Success;
            }
            catch (IOException)
            {
                return DokanResult.AccessDenied;
            }
        }

        public NtStatus UnlockFile(string fileName, long offset, long length, DokanFileInfo info)
        {
            try
            {
                ((FileStream)(info.Context)).Unlock(offset, length);
                return DokanResult.Success;
            }
            catch (IOException)
            {
                return DokanResult.AccessDenied;
            }
        }

        public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("GetFreeSpace");
#endif
            var dinfo = DriveInfo.GetDrives().Single(di => string.Equals(di.RootDirectory.Name, Path.GetPathRoot(GetPath_RW("\\")), StringComparison.OrdinalIgnoreCase));

            freeBytesAvailable = dinfo.TotalFreeSpace;
            totalNumberOfBytes = dinfo.TotalSize;
            totalNumberOfFreeBytes = dinfo.AvailableFreeSpace;
            return DokanResult.Success;
        }

        public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features,
            out string fileSystemName, out uint maximumComponentLength, DokanFileInfo info)
        {
#if TRACE
            Console.WriteLine("GetVolInfo");
#endif
            volumeLabel = "DOKAN";
            fileSystemName = "NTFS";
            maximumComponentLength = 256;

            features = FileSystemFeatures.CasePreservedNames | FileSystemFeatures.CaseSensitiveSearch |
                       FileSystemFeatures.PersistentAcls | FileSystemFeatures.SupportsRemoteStorage |
                       FileSystemFeatures.UnicodeOnDisk;

            return DokanResult.Success;
        }

        public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity security, AccessControlSections sections,
            DokanFileInfo info)
        {
            var filePath = GetPath(fileName);
#if TRACE
            Console.WriteLine("GetFileSecurity : " + fileName);
#endif
            try
            {
                security = info.IsDirectory
                    ? (FileSystemSecurity)Directory.GetAccessControl(filePath)
                    : File.GetAccessControl(filePath);
                return DokanResult.Success;
            }
            catch (UnauthorizedAccessException)
            {
                security = null;
                return DokanResult.AccessDenied;
            }
        }

        public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security, AccessControlSections sections,
            DokanFileInfo info)
        {
            var filePath = GetPath(fileName);
#if TRACE
            Console.WriteLine("SetFileSecurity : " + fileName);
#endif
            try
            {
                if (info.IsDirectory)
                {
                    Directory.SetAccessControl(filePath, (DirectorySecurity)security);
                }
                else
                {
                    File.SetAccessControl(filePath, (FileSecurity)security);
                }
                return DokanResult.Success;
            }
            catch (UnauthorizedAccessException)
            {
                return DokanResult.AccessDenied;
            }
        }

        public NtStatus Mounted(DokanFileInfo info)
        {
            return DokanResult.Success;
        }

        public NtStatus Unmounted(DokanFileInfo info)
        {
            return DokanResult.Success;
        }

        public NtStatus FindStreams(string fileName, IntPtr enumContext, out string streamName, out long streamSize,
            DokanFileInfo info)
        {
            streamName = string.Empty;
            streamSize = 0;
            return DokanResult.NotImplemented;
        }

        public NtStatus FindStreams(string fileName, out IList<FileInformation> streams, DokanFileInfo info)
        {
            streams = new List<FileInformation>();
            return DokanResult.NotImplemented;
        }

        public IList<FileInformation> FindFilesHelper(string fileName, string searchPattern)
        {
            IList<FileInformation> files = new List<FileInformation>();
            IList<FileInformation> tmp;
            foreach (FS fs in fsl) {
                if (Directory.Exists(combine(fs.TLD, fileName))||File.Exists(combine(fs.TLD, fileName))) {
                    tmp = new DirectoryInfo(combine(fs.TLD, fileName))
                    .EnumerateFileSystemInfos()
                    .Where(finfo => DokanHelper.DokanIsNameInExpression(searchPattern, finfo.Name, true))
                    .Select(finfo => new FileInformation
                    {
                        Attributes = finfo.Attributes,
                        CreationTime = finfo.CreationTime,
                        LastAccessTime = finfo.LastAccessTime,
                        LastWriteTime = finfo.LastWriteTime,
                        Length = (finfo as FileInfo)?.Length ?? 0,
                        FileName = finfo.Name
                    }).ToArray();
                    files = files.Union(tmp, new FileCompInfo()).ToArray();
                }
            }
            return files;
        }

        public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IList<FileInformation> files,
            DokanFileInfo info)
        {
            files = FindFilesHelper(fileName, searchPattern);
#if TRACE
            Console.WriteLine("FindFilesWithPattern : "+fileName);
#endif
            return DokanResult.Success;
        }
#endregion
    }
}
