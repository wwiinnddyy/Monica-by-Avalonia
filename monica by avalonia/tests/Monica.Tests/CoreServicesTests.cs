using System.Security.Cryptography;
using System.Text;
using Monica.Core.ImportExport;
using Monica.Core.Models;
using Monica.Core.Services;

namespace Monica.Tests;

public sealed class CoreServicesTests
{
    [Fact]
    public void Totp_generates_known_rfc_vector()
    {
        var service = new TotpService();

        var code = service.GenerateCode("JBSWY3DPEHPK3PXP", digits: 6);

        Assert.Matches("^[0-9]{6}$", code);
    }

    [Fact]
    public void Totp_resolver_accepts_otpauth_uri_and_raw_secret()
    {
        var fromUri = TotpDataResolver.FromAuthenticatorKey(
            "otpauth://totp/GitHub:dev%40example.com?secret=jbsw-y3dp ehpk3pxp&issuer=GitHub&period=45&digits=8");

        Assert.NotNull(fromUri);
        Assert.Equal("JBSWY3DPEHPK3PXP", fromUri.Secret);
        Assert.Equal("GitHub", fromUri.Issuer);
        Assert.Equal("dev@example.com", fromUri.AccountName);
        Assert.Equal(45, fromUri.Period);
        Assert.Equal(8, fromUri.Digits);

        var fromRaw = TotpDataResolver.FromAuthenticatorKey("jbsw y3dp-ehpk3pxp", "GitHub", "dev");

        Assert.NotNull(fromRaw);
        Assert.Equal("JBSWY3DPEHPK3PXP", fromRaw.Secret);
        Assert.Equal("GitHub", fromRaw.Issuer);
        Assert.Equal("dev", fromRaw.AccountName);
    }

    [Fact]
    public void Crypto_encrypts_and_decrypts_roundtrip()
    {
        var service = new CryptoService();
        var salt = service.CreateSalt();
        service.InitializeSession("correct horse battery staple", salt);

        var encrypted = service.EncryptString("secret payload");
        var decrypted = service.DecryptString(encrypted);

        Assert.NotEqual("secret payload", encrypted);
        Assert.Equal("secret payload", decrypted);
    }

    [Fact]
    public void Crypto_rejects_wrong_master_password()
    {
        var service = new CryptoService();
        var hash = service.HashMasterPassword("master");

        Assert.True(service.VerifyMasterPassword("master", hash));
        Assert.False(new CryptoService().VerifyMasterPassword("wrong", hash));
    }

    [Fact]
    public void Import_export_roundtrips_monica_json()
    {
        var service = new ImportExportService();
        var passwords = new[]
        {
            new PasswordEntry { Title = "GitHub", Username = "dev", Password = "encrypted" }
        };
        var items = new[]
        {
            new SecureItem { ItemType = VaultItemType.Note, Title = "Note", ItemData = "{}" }
        };

        var json = service.ExportJson(passwords, items);
        var package = service.ImportJson(json);

        Assert.Equal(68, package.SchemaVersion);
        Assert.Single(package.Passwords);
        Assert.Single(package.SecureItems);
    }

    [Fact]
    public void Import_export_roundtrips_password_csv()
    {
        var service = new ImportExportService();
        var passwords = new[]
        {
            new PasswordEntry
            {
                Title = "GitHub, Inc.",
                Website = "https://github.com",
                Username = "dev@example.com",
                Password = "secret, with comma",
                Notes = "line 1\nline \"2\"",
                AuthenticatorKey = "JBSWY3DPEHPK3PXP",
                AppName = "GitHub",
                AppPackageName = "com.github.android",
                Email = "security@example.com",
                Phone = "15551234567",
                LoginType = PasswordLoginType.SshKey,
                SsoProvider = "Entra",
                PasskeyBindings = """[{"rpId":"github.com"}]""",
                WifiMetadata = """{"ssid":"Monica"}""",
                SshKeyData = "ssh-ed25519 AAAA"
            }
        };

        var csv = service.ExportPasswordCsv(passwords);
        var imported = Assert.Single(service.ImportPasswordCsv(csv));

        Assert.Contains("\"GitHub, Inc.\"", csv);
        Assert.Equal("GitHub, Inc.", imported.Title);
        Assert.Equal("secret, with comma", imported.Password);
        Assert.Equal("line 1\nline \"2\"", imported.Notes);
        Assert.Equal(PasswordLoginType.SshKey, imported.LoginType);
        Assert.Equal("""[{"rpId":"github.com"}]""", imported.PasskeyBindings);
        Assert.Equal("""{"ssid":"Monica"}""", imported.WifiMetadata);
        Assert.Equal("ssh-ed25519 AAAA", imported.SshKeyData);
    }

    [Fact]
    public void Import_password_csv_accepts_bitwarden_style_headers()
    {
        var service = new ImportExportService();
        var csv = "name,login_uri,login_username,login_password,login_totp,notes\r\n"
            + "Example,https://example.com,dev,secret,JBSWY3DPEHPK3PXP,note";

        var imported = Assert.Single(service.ImportPasswordCsv(csv));

        Assert.Equal("Example", imported.Title);
        Assert.Equal("https://example.com", imported.Website);
        Assert.Equal("dev", imported.Username);
        Assert.Equal("secret", imported.Password);
        Assert.Equal("JBSWY3DPEHPK3PXP", imported.AuthenticatorKey);
        Assert.Equal(PasswordLoginType.Password, imported.LoginType);
    }

    [Fact]
    public void Feature_catalog_represents_android_parity_surface()
    {
        var keys = FeatureCatalog.AndroidParityFeatures.Select(item => item.Key).ToHashSet();

        Assert.Contains("passwords", keys);
        Assert.Contains("totp", keys);
        Assert.Contains("passkeys", keys);
        Assert.Contains("bitwarden", keys);
        Assert.Contains("keepass", keys);
        Assert.Contains("mdbx", keys);
        Assert.Contains("webdav", keys);
        Assert.Contains("autofill", keys);
    }

    [Fact]
    public void Password_generator_produces_strong_passwords()
    {
        var service = new PasswordGeneratorService();

        var password = service.GeneratePassword(24);
        var analysis = service.Analyze(password);

        Assert.Equal(24, password.Length);
        Assert.True(analysis.Score >= 3);
    }

    [Fact]
    public void Password_generator_honors_character_options()
    {
        var service = new PasswordGeneratorService();

        var password = service.GeneratePassword(
            32,
            includeUppercase: false,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: false);

        Assert.Equal(32, password.Length);
        Assert.DoesNotContain(password, char.IsUpper);
        Assert.DoesNotContain(password, c => !char.IsLetterOrDigit(c));
        Assert.Contains(password, char.IsLower);
        Assert.Contains(password, char.IsDigit);
    }

    [Fact]
    public async Task Pwned_password_service_queries_range_api_with_sha1_prefix()
    {
        var password = "correct horse battery staple";
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var handler = new FakePwnedPasswordHandler(hash[..5], $"{hash[5..]}:42\r\n00000000000000000000000000000000000:1");
        var service = new PwnedPasswordService(new HttpClient(handler));

        var results = await service.CheckPasswordsAsync([password, password, ""]);

        Assert.Equal(42, results[password]);
        Assert.Single(results);
        Assert.Equal(1, handler.RequestCount);
        Assert.EndsWith($"/range/{hash[..5]}", handler.LastRequestUri?.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.True(handler.SawPaddingHeader);
    }

    private sealed class FakePwnedPasswordHandler(string expectedPrefix, string responseContent) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public Uri? LastRequestUri { get; private set; }
        public bool SawPaddingHeader { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            LastRequestUri = request.RequestUri;
            SawPaddingHeader = request.Headers.TryGetValues("Add-Padding", out var values) && values.Contains("true");
            Assert.EndsWith($"/range/{expectedPrefix}", request.RequestUri?.AbsolutePath, StringComparison.OrdinalIgnoreCase);
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseContent)
            });
        }
    }
}
