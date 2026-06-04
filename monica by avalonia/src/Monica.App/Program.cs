using Avalonia;
using Monica.Core.Services;
using Monica.Data;
using System;
using System.IO;

namespace Monica.App;

class Program
{
    private static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Monica by Avalonia", "crash.log");

    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            File.AppendAllText(LogPath, $"[UnhandledException] {e.ExceptionObject}\n");
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            File.AppendAllText(LogPath, $"[UnobservedTaskException] {e.Exception}\n");
            e.SetObserved();
        };

        try
        {
            File.WriteAllText(LogPath, $"[Start] {DateTime.Now}\n");

            if (args.Length > 0 && string.Equals(args[0], "--smoke-vault", StringComparison.Ordinal))
            {
                return RunVaultSmokeTestAsync(args).GetAwaiter().GetResult();
            }

            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            File.AppendAllText(LogPath, $"[Fatal] {ex}\n");
            throw;
        }
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    private static async Task<int> RunVaultSmokeTestAsync(string[] args)
    {
        try
        {
            if (args.Length != 4)
            {
                Console.Error.WriteLine("Usage: Monica.App --smoke-vault <dbPath> <correctPassword> <wrongPassword>");
                return 2;
            }

            var factory = new SqliteConnectionFactory(args[1]);
            var migrator = new DatabaseMigrator(factory);
            var store = new VaultCredentialStore(factory, migrator);
            var crypto = new CryptoService();
            var credential = await store.GetAsync();
            if (credential is null)
            {
                credential = crypto.HashMasterPassword(args[2]);
                await store.SaveAsync(credential);
            }

            if (new CryptoService().VerifyMasterPassword(args[3], credential))
            {
                Console.Error.WriteLine("Wrong password was accepted.");
                return 3;
            }

            var unlockCrypto = new CryptoService();
            if (!unlockCrypto.VerifyMasterPassword(args[2], credential))
            {
                Console.Error.WriteLine("Correct password was rejected.");
                return 4;
            }

            var encrypted = unlockCrypto.EncryptString("monica-aot-smoke");
            if (!string.Equals("monica-aot-smoke", unlockCrypto.DecryptString(encrypted), StringComparison.Ordinal))
            {
                Console.Error.WriteLine("Encryption roundtrip failed.");
                return 5;
            }

            Console.WriteLine("Vault smoke test passed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }
}
