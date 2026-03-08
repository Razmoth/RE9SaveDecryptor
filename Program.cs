using RE9SaveDecryptor.Types;
using System.CommandLine;
using System.Globalization;

Argument<ulong> seedArgument = new("seed");
Argument<DirectoryInfo> directoryArgument = new("directory");

directoryArgument.AcceptExistingOnly();
seedArgument.CustomParser = result =>
{
    if (!result.Tokens.Any())
    {
        result.AddError("Invalid seed. Use integer or 0x hex format.");
        return 0;
    }

    string? str = result.Tokens[0].Value;

    NumberStyles styles = NumberStyles.Integer;
    if (str.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
    {
        str = str[2..];
        styles = NumberStyles.HexNumber;
    }

    if (!ulong.TryParse(str, styles, CultureInfo.InvariantCulture, out ulong value))
    {
        result.AddError("Invalid seed. Use integer or 0x hex format.");
        return 0;
    }
    
    return value;
};

RootCommand rootCommand = [directoryArgument, seedArgument];
rootCommand.SetAction(result =>
{
    ulong seed = result.GetValue(seedArgument);
    DirectoryInfo directory = result.GetValue(directoryArgument)!;
    Main(seed, directory);
});

ParseResult parseResult = rootCommand.Parse(args);
await parseResult.InvokeAsync();

static void Main(ulong seed, DirectoryInfo directory)
{
    string outputDirectoryPath = Path.Combine(AppContext.BaseDirectory, "Output");
    DirectoryInfo outputDirectory = Directory.CreateDirectory(outputDirectoryPath);
    foreach(FileInfo file in directory.EnumerateFiles("*.bin"))
    {
        string outputPath = Path.Combine(outputDirectory.FullName, file.Name);

        using FileStream inStream = file.OpenRead();
        using FileStream outStream = File.OpenWrite(outputPath);

        DSSSFile dsssFile = new(inStream);
        dsssFile.Decrypt(inStream, outStream, ~seed);
        Console.WriteLine($"Decrypted {file.Name} !!");
    }
}