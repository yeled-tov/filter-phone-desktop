using System.Text;
using System.Text.Json.Nodes;
using FilterPhone.Core.Ipc;

namespace FilterPhone.Core.Tests;

public class IpcProtocolTests
{
    [Fact]
    public async Task Frames_round_trip()
    {
        using var ms = new MemoryStream();
        var req = new IpcProtocol.Request("abc-1", IpcProtocol.Commands.Enroll, new JsonObject { ["code"] = "ABCDE-FGHJK" });
        await IpcProtocol.WriteFrameAsync(ms, IpcProtocol.SerializeRequest(req), IpcProtocol.MaxRequestBytes, default);
        ms.Position = 0;
        var parsed = IpcProtocol.ParseRequest(await IpcProtocol.ReadFrameAsync(ms, IpcProtocol.MaxRequestBytes, default));
        Assert.Equal("abc-1", parsed.Id);
        Assert.Equal("enroll", parsed.Command);
        Assert.Equal("ABCDE-FGHJK", parsed.Args["code"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("""{"v":1,"id":"a","cmd":"uninstall"}""")]
    [InlineData("""{"v":1,"id":"a","cmd":"status","extra":1}""")]
    [InlineData("""{"v":2,"id":"a","cmd":"status"}""")]
    [InlineData("""{"v":1,"id":"a b","cmd":"status"}""")]
    [InlineData("""{"v":1,"id":"a","cmd":"status","args":[1]}""")]
    [InlineData("""[1,2]""")]
    [InlineData("""not json""")]
    public void Rejects_anything_outside_the_protocol(string json) =>
        Assert.Throws<InvalidDataException>(() => IpcProtocol.ParseRequest(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public async Task Oversized_and_empty_frames_are_rejected()
    {
        using var ms = new MemoryStream([0xFF, 0xFF, 0xFF, 0x7F]);
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcProtocol.ReadFrameAsync(ms, IpcProtocol.MaxRequestBytes, default));
        using var empty = new MemoryStream([0, 0, 0, 0]);
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcProtocol.ReadFrameAsync(empty, IpcProtocol.MaxRequestBytes, default));
        using var sink = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            IpcProtocol.WriteFrameAsync(sink, new byte[IpcProtocol.MaxRequestBytes + 1], IpcProtocol.MaxRequestBytes, default));
    }

    [Fact]
    public void Argument_validation()
    {
        var args = new JsonObject { ["name"] = "מחשב‮", ["n"] = 5 };
        Assert.Throws<InvalidDataException>(() => IpcProtocol.OptionalString(args, "name", 60, IpcProtocol.DeviceNamePattern()));
        Assert.Throws<InvalidDataException>(() => IpcProtocol.OptionalString(args, "n", 60));
        Assert.Null(IpcProtocol.OptionalString(args, "missing", 60));
        Assert.Throws<InvalidDataException>(() => IpcProtocol.RejectUnknownArgs(args, "name"));
        Assert.Equal("מחשב של משה", IpcProtocol.OptionalString(new JsonObject { ["name"] = "מחשב של משה" }, "name", 60,
            IpcProtocol.DeviceNamePattern()));
    }
}
