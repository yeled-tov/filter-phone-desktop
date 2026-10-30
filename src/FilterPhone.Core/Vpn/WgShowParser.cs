using System.Globalization;

namespace FilterPhone.Core.Vpn;

public sealed record PeerTransfer(string PublicKey, DateTimeOffset? LatestHandshake, long RxBytes, long TxBytes);

/// <summary>Parses the tab-separated output of <c>wg show &lt;tunnel&gt; latest-handshakes|transfer</c>.</summary>
public static class WgShowParser
{
    public static IReadOnlyDictionary<string, DateTimeOffset?> ParseLatestHandshakes(string output)
    {
        var result = new Dictionary<string, DateTimeOffset?>(StringComparer.Ordinal);
        foreach (var line in Lines(output))
        {
            var parts = line.Split('\t');
            if (parts.Length != 2 || !WireGuardKeys.IsValidKey(parts[0])
                || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var epoch))
            {
                continue;
            }
            result[parts[0]] = epoch == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(epoch);
        }
        return result;
    }

    public static IReadOnlyDictionary<string, (long Rx, long Tx)> ParseTransfer(string output)
    {
        var result = new Dictionary<string, (long, long)>(StringComparer.Ordinal);
        foreach (var line in Lines(output))
        {
            var parts = line.Split('\t');
            if (parts.Length != 3 || !WireGuardKeys.IsValidKey(parts[0])
                || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var rx)
                || !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var tx))
            {
                continue;
            }
            result[parts[0]] = (rx, tx);
        }
        return result;
    }

    private static string[] Lines(string output) =>
        output.Replace("\r", string.Empty, StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
