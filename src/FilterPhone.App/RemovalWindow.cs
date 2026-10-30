using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using FilterPhone.Core;
using FilterPhone.Core.Ipc;

namespace FilterPhone.App;

/// <summary>
/// Shown by the uninstaller (FilterPhone.exe --authorize-removal): removing FilterPhone from an activated PC
/// needs a removal code that FilterPhone issues in its dashboard for this PC. The code is checked by the
/// protection service; this window only collects it. Exit code 0 = authorized, 1 = cancelled.
/// </summary>
public sealed class RemovalWindow : Window
{
    private readonly TextBox _code = new()
    {
        FlowDirection = FlowDirection.LeftToRight,
        MaxLength = 20,
        FontSize = 22,
        FontFamily = new FontFamily("Consolas"),
        CharacterCasing = CharacterCasing.Upper,
        HorizontalContentAlignment = HorizontalAlignment.Center,
    };
    private readonly TextBlock _error = new() { Foreground = new SolidColorBrush(Color.FromRgb(0xB4, 0x23, 0x18)), Margin = new Thickness(0, 0, 0, 8) };
    private readonly Button _ok = new() { Content = "המשך בהסרה", IsDefault = true };

    public bool Authorized { get; private set; }

    public RemovalWindow()
    {
        Title = "הסרת FilterPhone למחשב";
        FlowDirection = FlowDirection.RightToLeft;
        Width = 500;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = (Brush)Application.Current.Resources["Page"];
        Foreground = (Brush)Application.Current.Resources["Ink"];
        Topmost = true;

        _ok.Style = (Style)Application.Current.Resources["FilledButton"];
        _ok.Margin = new Thickness(0, 0, 10, 8);
        _ok.MinHeight = 44;
        _ok.Click += async (_, _) => await SubmitAsync();
        var cancel = new Button { Content = "ביטול", IsCancel = true };
        cancel.Click += (_, _) => Close();
        var support = new Button { Content = "פנייה לתמיכה" };
        support.Click += (_, _) => SupportLauncher.Open(SupportLauncher.Number(string.Empty),
            "שלום, אני רוצה להסיר את FilterPhone מהמחשב ואני צריך קוד הסרה.", ProductConfig.Current.SupportEmail);

        var buttons = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
        buttons.Children.Add(_ok);
        buttons.Children.Add(cancel);
        buttons.Children.Add(support);

        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = "כדי להסיר את FilterPhone צריך קוד הסרה", Style = (Style)Application.Current.Resources["Title"], Margin = new Thickness(0, 0, 0, 10) });
        panel.Children.Add(new TextBlock
        {
            Text = "המחשב הזה מוגן על ידי FilterPhone. את קוד ההסרה מקבלים מ-FilterPhone, והוא מתאים רק למחשב הזה. " +
                   "בלי הקוד ההגנה נשארת פעילה והתוכנה לא תוסר.",
            Margin = new Thickness(0, 0, 0, 12),
        });
        panel.Children.Add(new TextBlock { Text = "קוד הסרה (10 תווים, למשל ABCDE-12345):", Style = (Style)Application.Current.Resources["Hint"] });
        panel.Children.Add(_code);
        panel.Children.Add(_error);
        panel.Children.Add(buttons);
        Content = new Border { Style = (Style)Application.Current.Resources["CardBorder"], Margin = new Thickness(16), Child = panel };
        Loaded += (_, _) => Keyboard.Focus(_code);
    }

    private async Task SubmitAsync()
    {
        var code = _code.Text.Trim();
        if (code.Any(c => char.IsLetter(c) && !char.IsAsciiLetter(c)))
        {
            _error.Text = "נראה שהמקלדת בעברית. החליפו לאנגלית (Alt+Shift) והקלידו את הקוד שוב.";
            return;
        }
        if (code.Count(char.IsAsciiLetterOrDigit) != 10 || code.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or ' ')))
        {
            _error.Text = "הקלידו את כל 10 התווים של הקוד (אותיות באנגלית ומספרים).";
            return;
        }
        _ok.IsEnabled = false;
        _error.Text = "בודק את הקוד…";
        try
        {
            var reply = await ServiceClient.SendAsync(IpcProtocol.Commands.AuthorizeRemoval, new JsonObject { ["code"] = code },
                TimeSpan.FromSeconds(30));
            if (reply.Ok)
            {
                Authorized = true;
                Close();
                return;
            }
            _error.Text = reply.Error == IpcProtocol.Errors.RateLimited
                ? "יותר מדי ניסיונות. נסו שוב בעוד כמה דקות."
                : "הקוד לא נכון או שפג תוקפו. בקשו קוד חדש מ-FilterPhone.";
        }
        catch (ServiceUnavailableException)
        {
            _error.Text = "שירות ההגנה של FilterPhone לא עונה. הפעילו מחדש את המחשב ונסו שוב.";
        }
        catch (Exception e) when (e is TimeoutException or OperationCanceledException or System.IO.IOException or System.IO.InvalidDataException)
        {
            _error.Text = "שירות ההגנה של FilterPhone לא עונה. נסו שוב.";
        }
        finally
        {
            _ok.IsEnabled = true;
        }
    }
}
