using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using FilterPhone.Core;
using FilterPhone.Core.Support;

namespace FilterPhone.App;

/// <summary>
/// Opens a prepared, editable support message. Nothing is ever sent automatically: WhatsApp or the mail
/// client opens with the text and the user presses "send" there. Attachments are never added silently.
/// </summary>
public static partial class SupportLauncher
{
    public enum Channel
    {
        WhatsAppDesktop,
        WhatsAppWeb,
        Email,
        None,
    }

    /// <summary>True when an application (WhatsApp Desktop) is registered for the whatsapp: URI protocol.</summary>
    public static unsafe bool WhatsAppDesktopInstalled()
    {
        const int ASSOCF_IS_PROTOCOL = 0x00001000;
        const int ASSOCSTR_FRIENDLYAPPNAME = 4;
        uint size = 512;
        var buffer = new char[size];
        fixed (char* b = buffer)
        {
            return AssocQueryString(ASSOCF_IS_PROTOCOL, ASSOCSTR_FRIENDLYAPPNAME, "whatsapp", null, b, ref size) == 0;
        }
    }

    public static Channel Open(string number, string message, string email)
    {
        if (number.Length > 0 && WhatsAppDesktopInstalled() && TryShell(SupportMessage.WhatsAppDesktopUri(number, message)))
        {
            return Channel.WhatsAppDesktop;
        }
        if (email.Length > 0 && TryShell(SupportMessage.MailtoUri(email, "פנייה לתמיכה — FilterPhone למחשב", message)))
        {
            return Channel.Email;
        }
        if (number.Length > 0 && TryShell(SupportMessage.WhatsAppWebUri(number, message)))
        {
            return Channel.WhatsAppWeb;
        }
        return Channel.None;
    }

    public static bool OpenEmail(string email, string message) =>
        email.Length > 0 && TryShell(SupportMessage.MailtoUri(email, "פנייה לתמיכה — FilterPhone למחשב", message));

    /// <summary>Saves the (already redacted) report where the user can attach it themselves, and shows it in Explorer.</summary>
    public static string SaveReportForAttachment(string report)
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var path = Path.Combine(docs, $"FilterPhone-diagnostics-{DateTime.Now:yyyyMMdd-HHmm}.txt");
        File.WriteAllText(path, report, System.Text.Encoding.UTF8);
        Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
        {
            ArgumentList = { "/select," + path },
            UseShellExecute = false,
        });
        return path;
    }

    public static string Number(string fromServer) =>
        fromServer.Length > 0 ? fromServer : ProductConfig.Current.SupportWhatsApp;

    private static bool TryShell(Uri uri)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    [LibraryImport("shlwapi.dll", EntryPoint = "AssocQueryStringW", StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial int AssocQueryString(int flags, int str, string assoc, string? extra, char* output, ref uint size);
}
