using Monica.App.Services;
using Monica.App.ViewModels;
using Monica.Core.ImportExport;
using Monica.Core.Models;
using Monica.Core.Services;
using Monica.Data;
using Monica.Data.Repositories;
using Monica.Platform.Services;

namespace Monica.Tests;

public sealed class AppSettingsTests
{
    [Fact]
    public async Task App_settings_roundtrip_interactive_values()
    {
        var path = GetTempPath();
        var first = new AppSettingsService(path);
        await first.LoadAsync();
        first.Current.Language = "zh-CN";
        first.Current.Theme = "dark";
        first.Current.AutoLockEnabled = false;
        first.Current.ClipboardClearSeconds = 120;
        first.Current.WebDavEnabled = true;
        first.Current.WebDavServerUrl = "https://dav.example.com";
        first.Current.SyncConflictStrategy = "local-wins";
        await first.SaveAsync();

        var second = new AppSettingsService(path);
        await second.LoadAsync();

        Assert.Equal("zh-CN", second.Current.Language);
        Assert.Equal("dark", second.Current.Theme);
        Assert.False(second.Current.AutoLockEnabled);
        Assert.Equal(120, second.Current.ClipboardClearSeconds);
        Assert.True(second.Current.WebDavEnabled);
        Assert.Equal("https://dav.example.com", second.Current.WebDavServerUrl);
        Assert.Equal("local-wins", second.Current.SyncConflictStrategy);
    }

    [Fact]
    public async Task App_settings_allows_archive_startup_section()
    {
        var path = GetTempPath();
        var settings = new AppSettingsService(path);
        await settings.LoadAsync();
        settings.Current.StartupSection = "Archive";
        await settings.SaveAsync();

        var reloaded = new AppSettingsService(path);
        await reloaded.LoadAsync();

        Assert.Equal("Archive", reloaded.Current.StartupSection);
    }

    [Fact]
    public async Task App_settings_allows_security_analysis_startup_section()
    {
        var path = GetTempPath();
        var settings = new AppSettingsService(path);
        await settings.LoadAsync();
        settings.Current.StartupSection = "SecurityAnalysis";
        await settings.SaveAsync();

        var reloaded = new AppSettingsService(path);
        await reloaded.LoadAsync();

        Assert.Equal("SecurityAnalysis", reloaded.Current.StartupSection);
    }

    [Fact]
    public async Task ViewModel_initializes_chinese_language_and_saves_changed_settings()
    {
        var settingsPath = GetTempPath();
        var settingsService = new AppSettingsService(settingsPath);
        await settingsService.LoadAsync();
        settingsService.Current.Language = "zh-CN";
        settingsService.Current.Theme = "light";
        await settingsService.SaveAsync();

        var viewModel = CreateViewModel(settingsPath);
        await viewModel.InitializeAsync();

        Assert.Equal("设置", viewModel.L.Settings);
        Assert.Equal("创建 Monica 保险库", viewModel.LoginTitle);
        Assert.Contains(viewModel.Capabilities, capability => capability.Title == "密码" && capability.Status == "可用");

        viewModel.WebDavEnabled = true;
        viewModel.WebDavServerUrl = "https://dav.example.com";
        await Task.Delay(250);

        var reloaded = new AppSettingsService(settingsPath);
        await reloaded.LoadAsync();
        Assert.True(reloaded.Current.WebDavEnabled);
        Assert.Equal("https://dav.example.com", reloaded.Current.WebDavServerUrl);
    }

    private static MainWindowViewModel CreateViewModel(string settingsPath)
    {
        var databasePath = Path.Combine(Path.GetTempPath(), "monica-tests", $"{Guid.NewGuid():N}.db");
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        var factory = new SqliteConnectionFactory(databasePath);
        var migrator = new DatabaseMigrator(factory);
        return new MainWindowViewModel(
            new MonicaRepository(factory, migrator),
            new VaultCredentialStore(factory, migrator),
            new CryptoService(),
            new TotpService(),
            new PasswordGeneratorService(),
            new ImportExportService(),
            new PlatformCapabilityService(),
            new NoopClipboardService(),
            new MdbxVaultService(),
            new NoopPasswordAttachmentFileService(),
            new NoopPasswordEditorDialogService(),
            new NoopPasswordDetailDialogService(),
            new NoopCategoryPickerDialogService(),
            new AppSettingsService(settingsPath),
            new LocalizationService());
    }

    private static string GetTempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), "monica-tests", $"{Guid.NewGuid():N}.settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        return path;
    }

    private sealed class NoopClipboardService : IClipboardService
    {
        public Task SetTextAsync(string text, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class NoopPasswordEditorDialogService : IPasswordEditorDialogService
    {
        public Task<PasswordEditorViewModel?> ShowAsync(
            PasswordEntry? entry,
            IReadOnlyList<Category> categories,
            string plainPassword,
            IReadOnlyList<string>? siblingPasswords = null,
            IReadOnlyList<SecureItem>? notes = null,
            IReadOnlyList<CustomField>? customFields = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<PasswordEditorViewModel?>(null);
    }

    private sealed class NoopPasswordDetailDialogService : IPasswordDetailDialogService
    {
        public Task ShowAsync(
            PasswordEntry entry,
            IReadOnlyList<PasswordEntry> siblings,
            Category? category,
            SecureItem? boundNote,
            IReadOnlyList<Attachment> attachments,
            IReadOnlyList<CustomField> customFields,
            IReadOnlyList<PasswordHistoryDisplayItem> passwordHistory,
            Func<PasswordEntry, Task>? addAttachment,
            Func<Attachment, Task>? deleteAttachment,
            Func<PasswordHistoryEntry, Task>? deletePasswordHistory,
            Func<long, Task>? clearPasswordHistory,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class NoopPasswordAttachmentFileService : IPasswordAttachmentFileService
    {
        public Task<PasswordAttachmentFileDraft?> PickAndStoreAttachmentAsync(PasswordEntry entry, CancellationToken cancellationToken = default) =>
            Task.FromResult<PasswordAttachmentFileDraft?>(null);

        public Task DeleteStoredAttachmentAsync(string storagePath, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class NoopCategoryPickerDialogService : ICategoryPickerDialogService
    {
        public Task<PasswordCategoryChoice?> ShowAsync(
            IReadOnlyList<Category> categories,
            long? selectedCategoryId = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<PasswordCategoryChoice?>(null);
    }
}
