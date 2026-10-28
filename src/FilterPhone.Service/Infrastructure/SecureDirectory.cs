using System.Security.AccessControl;
using System.Security.Principal;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// Creates the service data directories with an explicit, non-inherited ACL. C:\ProgramData lets standard
/// users create folders, so a pre-existing folder that is not owned by SYSTEM or Administrators is treated
/// as planted: its ACL and owner are reset and its contents are discarded before any secret is written.
/// </summary>
internal static class SecureDirectory
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    public static void EnsureAll()
    {
        EnsureRoot(Paths.DataRoot);
        Ensure(Paths.Secrets, usersCanRead: false);
        Ensure(Paths.Tunnel, usersCanRead: false);
        Ensure(Paths.Logs, usersCanRead: false);
        Ensure(Paths.Policy, usersCanRead: true);
        Ensure(Paths.Probe, usersCanRead: true);
    }

    private static void EnsureRoot(string path)
    {
        if (Directory.Exists(path) && new DirectoryInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            // A junction or symbolic link planted in place of our folder: remove the link itself, never its target.
            Directory.Delete(path);
        }
        if (Directory.Exists(path))
        {
            var owner = new DirectoryInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner is null || !(owner.Equals(System) || owner.Equals(Admins)))
            {
                // Planted by someone else: take it back and start clean.
                var info = new DirectoryInfo(path);
                var sec = new DirectorySecurity();
                sec.SetOwner(System);
                sec.SetAccessRuleProtection(true, false);
                sec.AddAccessRule(Rule(System, FileSystemRights.FullControl));
                sec.AddAccessRule(Rule(Admins, FileSystemRights.FullControl));
                info.SetAccessControl(sec);
                foreach (var entry in info.EnumerateFileSystemInfos())
                {
                    if (entry is DirectoryInfo d)
                    {
                        d.Delete(recursive: true);
                    }
                    else
                    {
                        entry.Delete();
                    }
                }
            }
        }
        Ensure(path, usersCanRead: false);
    }

    public static void Ensure(string path, bool usersCanRead)
    {
        var sec = new DirectorySecurity();
        sec.SetOwner(System);
        sec.SetAccessRuleProtection(true, false);
        sec.AddAccessRule(Rule(System, FileSystemRights.FullControl));
        sec.AddAccessRule(Rule(Admins, FileSystemRights.FullControl));
        if (usersCanRead)
        {
            sec.AddAccessRule(Rule(Users, FileSystemRights.ReadAndExecute));
        }
        if (!Directory.Exists(path))
        {
            new DirectoryInfo(path).Create(sec);
        }
        else
        {
            new DirectoryInfo(path).SetAccessControl(sec);
        }
    }

    /// <summary>Writes a file atomically (temp file + replace) so a crash never leaves a half-written secret.</summary>
    public static void WriteAllBytesAtomic(string path, byte[] data)
    {
        var tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            fs.Write(data);
        }
        File.Move(tmp, path, overwrite: true);
    }

    private static FileSystemAccessRule Rule(SecurityIdentifier sid, FileSystemRights rights) =>
        new(sid, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
            AccessControlType.Allow);
}
