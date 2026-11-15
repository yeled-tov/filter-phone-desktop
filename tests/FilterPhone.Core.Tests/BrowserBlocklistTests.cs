using FilterPhone.Core.Policy;

namespace FilterPhone.Core.Tests;

public class BrowserBlocklistTests
{
    [Theory]
    [InlineData("Microsoft Edge", "Microsoft Corporation", "msedge.exe")]
    [InlineData("Mozilla Firefox", "Mozilla Corporation", "firefox.exe")]
    [InlineData("Firefox", "Mozilla", "firefox.exe")]
    [InlineData("Opera", "Opera Software", "opera.exe")]
    [InlineData("Brave", "Brave Software, Inc.", "brave.exe")]
    [InlineData("Vivaldi", "Vivaldi Technologies", "vivaldi.exe")]
    [InlineData("Chromium", "The Chromium Authors", "chromium.exe")]
    [InlineData("Tor Browser", "The Tor Project", "firefox.exe")]
    [InlineData("Internet Explorer", "Microsoft Corporation", "iexplore.exe")]
    [InlineData("DuckDuckGo", "DuckDuckGo", "duckduckgo.exe")]
    public void Known_browsers_are_blocked(string product, string company, string file) =>
        Assert.True(BrowserBlocklist.IsBlockedBrowser(product, company, file));

    [Theory]
    [InlineData("Google Chrome", "Google LLC", "chrome.exe")]
    [InlineData("Google Chrome for Testing", "Google LLC", "chrome.exe")]
    public void Chrome_is_allowed(string product, string company, string file) =>
        Assert.False(BrowserBlocklist.IsBlockedBrowser(product, company, file));

    [Theory]
    [InlineData("Microsoft Office", "Microsoft Corporation", "winword.exe")]
    [InlineData("Windows Explorer", "Microsoft Corporation", "explorer.exe")]
    [InlineData("FilterPhone Desktop", "FilterPhone", "FilterPhone.exe")]
    [InlineData("Windows Security", "Microsoft Corporation", "MsMpEng.exe")]
    [InlineData("Some App", "Some Vendor", "myapp.exe")]
    public void Ordinary_and_security_programs_are_not_touched(string product, string company, string file) =>
        Assert.False(BrowserBlocklist.IsBlockedBrowser(product, company, file));

    [Fact]
    public void Product_name_wins_over_a_renamed_executable()
    {
        // Edge renamed to chrome.exe is still blocked by its product name.
        Assert.True(BrowserBlocklist.IsBlockedBrowser("Microsoft Edge", "Microsoft Corporation", "chrome.exe"));
        // Firefox renamed to notepad.exe is still blocked.
        Assert.True(BrowserBlocklist.IsBlockedBrowser("Firefox", "Mozilla", "notepad.exe"));
    }

    [Fact]
    public void Missing_version_info_falls_back_to_the_file_name()
    {
        Assert.True(BrowserBlocklist.IsBlockedBrowser(null, null, "firefox.exe"));
        Assert.True(BrowserBlocklist.IsBlockedBrowser("", "", "msedge.exe"));
        Assert.False(BrowserBlocklist.IsBlockedBrowser(null, null, "chrome.exe"));
        Assert.False(BrowserBlocklist.IsBlockedBrowser(null, null, "unknown.exe"));
    }

    [Fact]
    public void Generic_launcher_names_need_a_browser_vendor()
    {
        Assert.True(BrowserBlocklist.IsBlockedBrowser(null, "Yandex LLC", "browser.exe"));
        Assert.True(BrowserBlocklist.IsBlockedBrowser("Opera", "Opera Software", "launcher.exe"));
        Assert.False(BrowserBlocklist.IsBlockedBrowser(null, "Steam", "launcher.exe"));
        Assert.False(BrowserBlocklist.IsBlockedBrowser(null, "Some Game Studio", "browser.exe"));
    }

    [Theory]
    [InlineData(@"C:\Program Files\WindowsApps\Microsoft.WindowsStore_22410.1401.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe", true)]
    [InlineData(@"c:\program files\windowsapps\microsoft.windowsstore_12107.1001.15.0_x64__8wekyb3d8bbwe\winstore.app.exe", true)]
    [InlineData(@"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe\CalculatorApp.exe", false)]
    [InlineData(@"C:\Users\u\Downloads\WinStore.App.exe", false)]
    [InlineData(@"C:\Program Files\WindowsApps\Microsoft.WindowsStore_22410.1401.5.0_x64__8wekyb3d8bbwe\StoreDesktopExtension.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Only_the_microsoft_store_app_is_recognised_as_the_store(string? path, bool expected) =>
        Assert.Equal(expected, BrowserBlocklist.IsMicrosoftStore(path));
}
