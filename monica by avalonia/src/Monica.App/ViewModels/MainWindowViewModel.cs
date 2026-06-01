using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using Avalonia;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Monica.App.Services;
using Monica.Core.ImportExport;
using Monica.Core.Models;
using Monica.Core.Services;
using Monica.Data;
using Monica.Data.Repositories;
using Monica.Platform.Services;

namespace Monica.App.ViewModels;

public sealed record SettingsChoice(object Value, string Label);
public sealed record LocalizedPlatformCapability(string Key, string Title, string Description, string Status);
public sealed record TimelineEntry(string Title, string Description, string TimestampText, string OperationType, string ItemType);
public sealed record SecuritySummaryItem(string Label, string Value, string Detail);
public sealed record SecurityIssueItem(string Title, string Subtitle, string Category, string Severity, long PasswordId, PasswordEntry Entry, int SeverityWeight);
public sealed record PasswordHistoryDisplayItem(PasswordHistoryEntry Entry, string DisplayPassword, bool CanCopy);
public sealed record PasswordQuickAccessItem(PasswordEntry Entry, int OpenCount, string LastOpenedText, string Subtitle);
public sealed record PasswordFolderFilterChoice(long? Id, string Name, int Count);

public sealed partial class MainWindowViewModel : ObservableObject
{
    private const int PasswordHistoryLimit = 10;
    private const int PasswordQuickAccessLimit = 6;

    private enum QuickAccessSort
    {
        Recent,
        Frequent
    }

    private static readonly string[] KnownTwoFactorDomains =
    [
        "google.com",
        "gmail.com",
        "github.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "dropbox.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "reddit.com",
        "slack.com",
        "discord.com",
        "x.com",
        "twitter.com",
        "icloud.com",
        "outlook.com",
        "twitch.tv",
        "steam.com"
    ];

    private readonly IMonicaRepository _repository;
    private readonly ICryptoService _cryptoService;
    private readonly ITotpService _totpService;
    private readonly IPasswordGeneratorService _passwordGenerator;
    private readonly IPwnedPasswordService _pwnedPasswordService;
    private readonly IImportExportService _importExportService;
    private readonly IClipboardService _clipboardService;
    private readonly IMdbxVaultService _mdbxVaultService;
    private readonly IPasswordAttachmentFileService _passwordAttachmentFileService;
    private readonly IPasswordEditorDialogService _passwordEditorDialogService;
    private readonly IPasswordDetailDialogService _passwordDetailDialogService;
    private readonly ICategoryPickerDialogService _categoryPickerDialogService;
    private readonly IVaultCredentialStore _credentialStore;
    private readonly IAppSettingsService _settingsService;
    private readonly ILocalizationService _localization;
    private readonly IReadOnlyList<PlatformCapability> _sourceCapabilities;
    private IReadOnlyDictionary<long, IReadOnlyList<CustomField>> _passwordCustomFields = new Dictionary<long, IReadOnlyList<CustomField>>();
    private IReadOnlyDictionary<long, IReadOnlyList<Attachment>> _passwordAttachments = new Dictionary<long, IReadOnlyList<Attachment>>();
    private IReadOnlyDictionary<long, PasswordQuickAccessRecord> _passwordQuickAccessRecords = new Dictionary<long, PasswordQuickAccessRecord>();
    private IReadOnlyDictionary<long, CompromisedPasswordResult> _compromisedPasswordResults = new Dictionary<long, CompromisedPasswordResult>();
    private bool _hasCompromisedPasswordCheckResults;
    private bool _isApplyingSettings;

    public MainWindowViewModel(
        IMonicaRepository repository,
        IVaultCredentialStore credentialStore,
        ICryptoService cryptoService,
        ITotpService totpService,
        IPasswordGeneratorService passwordGenerator,
        IImportExportService importExportService,
        IPlatformCapabilityService platformCapabilityService,
        IClipboardService clipboardService,
        IMdbxVaultService mdbxVaultService,
        IPasswordAttachmentFileService passwordAttachmentFileService,
        IPasswordEditorDialogService passwordEditorDialogService,
        IPasswordDetailDialogService passwordDetailDialogService,
        ICategoryPickerDialogService categoryPickerDialogService,
        IAppSettingsService settingsService,
        ILocalizationService localization,
        IPwnedPasswordService? pwnedPasswordService = null)
    {
        _repository = repository;
        _credentialStore = credentialStore;
        _cryptoService = cryptoService;
        _totpService = totpService;
        _passwordGenerator = passwordGenerator;
        _pwnedPasswordService = pwnedPasswordService ?? new PwnedPasswordService();
        _importExportService = importExportService;
        _clipboardService = clipboardService;
        _mdbxVaultService = mdbxVaultService;
        _passwordAttachmentFileService = passwordAttachmentFileService;
        _passwordEditorDialogService = passwordEditorDialogService;
        _passwordDetailDialogService = passwordDetailDialogService;
        _categoryPickerDialogService = categoryPickerDialogService;
        _settingsService = settingsService;
        _localization = localization;
        _localization.PropertyChanged += (_, _) => RefreshLocalizedProperties();
        _sourceCapabilities = platformCapabilityService.GetCapabilities();
        CompromisedPasswordStatus = _localization.Get("CompromisedPasswordNotChecked");
        RefreshCapabilities();
        RefreshChoiceLabels();
    }

    public ILocalizationService L => _localization;
    public ObservableCollection<PasswordEntry> Passwords { get; } = [];
    public ObservableCollection<PasswordEntry> ArchivedPasswords { get; } = [];
    public ObservableCollection<PasswordEntry> DeletedPasswords { get; } = [];
    public ObservableCollection<SecureItem> NoteItems { get; } = [];
    public ObservableCollection<SecureItem> TotpItems { get; } = [];
    public ObservableCollection<SecureItem> WalletItems { get; } = [];
    public ObservableCollection<Category> Categories { get; } = [];
    public ObservableCollection<LocalizedPlatformCapability> Capabilities { get; } = [];
    public ObservableCollection<LocalMdbxDatabase> MdbxDatabases { get; } = [];
    public ObservableCollection<TimelineEntry> TimelineEntries { get; } = [];
    public ObservableCollection<SecuritySummaryItem> SecuritySummaryItems { get; } = [];
    public ObservableCollection<SecurityIssueItem> SecurityIssueItems { get; } = [];
    public ObservableCollection<SettingsChoice> LanguageOptions { get; } = [];
    public ObservableCollection<SettingsChoice> ThemeOptions { get; } = [];
    public ObservableCollection<SettingsChoice> StartupSectionOptions { get; } = [];
    public ObservableCollection<SettingsChoice> AutoLockMinuteOptions { get; } = [];
    public ObservableCollection<SettingsChoice> ClipboardSecondOptions { get; } = [];
    public ObservableCollection<SettingsChoice> ConflictStrategyOptions { get; } = [];
    public ObservableCollection<SettingsChoice> PasswordSortOptions { get; } = [];
    public ObservableCollection<PasswordFolderFilterChoice> PasswordFolderFilters { get; } = [];

    [ObservableProperty]
    private bool _isUnlocked;

    [ObservableProperty]
    private bool _isVaultInitialized;

    [ObservableProperty]
    private string _selectedSection = "Passwords";

    [ObservableProperty]
    private string _masterPassword = "";

    [ObservableProperty]
    private string _confirmMasterPassword = "";

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private string _statusMessage = "Locked";

    [ObservableProperty]
    private string _generatedPassword = "";

    [ObservableProperty]
    private int _generatorLength = 24;

    [ObservableProperty]
    private bool _generatorIncludeUppercase = true;

    [ObservableProperty]
    private bool _generatorIncludeLowercase = true;

    [ObservableProperty]
    private bool _generatorIncludeNumbers = true;

    [ObservableProperty]
    private bool _generatorIncludeSymbols = true;

    [ObservableProperty]
    private string _exportPreview = "";

    [ObservableProperty]
    private string _importJsonText = "";

    [ObservableProperty]
    private string _exportCsvPreview = "";

    [ObservableProperty]
    private string _importCsvText = "";

    [ObservableProperty]
    private string _newFolderName = "";

    [ObservableProperty]
    private PasswordFolderFilterChoice? _selectedPasswordFolderFilter;

    [ObservableProperty]
    private string _selectedPasswordSort = "updated-desc";

    [ObservableProperty]
    private bool _isCheckingCompromisedPasswords;

    [ObservableProperty]
    private string _compromisedPasswordStatus = "";

    [ObservableProperty]
    private SecureItem? _selectedNote;

    [ObservableProperty]
    private string _noteTitle = "";

    [ObservableProperty]
    private string _noteContent = "";

    [ObservableProperty]
    private string _noteTagsText = "";

    [ObservableProperty]
    private bool _noteIsMarkdown = true;

    [ObservableProperty]
    private bool _notePreviewMode;

    [ObservableProperty]
    private bool _noteIsFavorite;

    [ObservableProperty]
    private string _settingsLanguage = "system";

    [ObservableProperty]
    private string _settingsTheme = "system";

    [ObservableProperty]
    private string _startupSection = "Passwords";

    [ObservableProperty]
    private bool _autoLockEnabled = true;

    [ObservableProperty]
    private int _autoLockMinutes = 5;

    [ObservableProperty]
    private bool _clearClipboardEnabled = true;

    [ObservableProperty]
    private int _clipboardClearSeconds = 30;

    [ObservableProperty]
    private bool _requirePasswordBeforeExport = true;

    [ObservableProperty]
    private bool _minimizeToTray;

    [ObservableProperty]
    private bool _quickSearchEnabled = true;

    [ObservableProperty]
    private string _quickSearchHotkey = "Ctrl+Shift+Space";

    [ObservableProperty]
    private bool _browserIntegrationEnabled;

    [ObservableProperty]
    private int _browserIntegrationPort = 49152;

    [ObservableProperty]
    private bool _compactPasswordList;

    [ObservableProperty]
    private bool _webDavEnabled;

    [ObservableProperty]
    private string _webDavServerUrl = "";

    [ObservableProperty]
    private string _webDavUsername = "";

    [ObservableProperty]
    private string _webDavRemotePath = "/Monica";

    [ObservableProperty]
    private bool _webDavSyncOnStartup;

    [ObservableProperty]
    private bool _webDavSyncAfterChanges;

    [ObservableProperty]
    private string _syncConflictStrategy = "ask";

    [ObservableProperty]
    private bool _oneDriveEnabled;

    [ObservableProperty]
    private bool _mdbxLocalCacheEnabled = true;

    [ObservableProperty]
    private bool _quickFilterFavorite;

    [ObservableProperty]
    private bool _quickFilter2Fa;

    [ObservableProperty]
    private bool _quickFilterNotes;

    [ObservableProperty]
    private bool _quickFilterPasskey;

    [ObservableProperty]
    private bool _quickFilterBoundNote;

    [ObservableProperty]
    private bool _quickFilterUncategorized;

    [ObservableProperty]
    private bool _quickFilterLocalOnly;

    [ObservableProperty]
    private bool _quickFilterAttachments;

    public string SelectedSectionTitle => SectionTitle(SelectedSection);
    public string LoginTitle => IsVaultInitialized ? _localization.UnlockMonica : _localization.CreateMonicaVault;
    public string LoginDescription => IsVaultInitialized
        ? _localization.UnlockDescription
        : _localization.CreateVaultDescription;
    public string LoginButtonText => IsVaultInitialized ? _localization.Unlock : _localization.CreateVault;

    public string PasswordCountText => _localization.Format("PasswordCountFormat", Passwords.Count);
    public string ArchivedPasswordCountText => _localization.Format("ArchivedPasswordCountFormat", ArchivedPasswords.Count);
    public string DeletedPasswordCountText => _localization.Format("DeletedPasswordCountFormat", DeletedPasswords.Count);
    public string SelectedPasswordCountText => _localization.Format("SelectedPasswordCountFormat", SelectedPasswordCount);
    public bool CanStackSelectedPasswords => SelectedPasswordCount > 1;
    public bool CanManageSelectedPasswordFolder => SelectedPasswordFolderFilter?.Id is > 0;
    public Thickness PasswordListCardPadding => CompactPasswordList ? new Thickness(12, 8) : new Thickness(16);
    public double PasswordListAvatarSize => CompactPasswordList ? 36 : 48;
    public double PasswordListAvatarFontSize => CompactPasswordList ? 14 : 18;
    public double PasswordListRowMinHeight => CompactPasswordList ? 40 : 54;
    public CornerRadius PasswordListAvatarCornerRadius => new(PasswordListAvatarSize / 2);
    public Thickness PasswordListContentMargin => CompactPasswordList ? new Thickness(10, 0, 0, 0) : new Thickness(14, 0, 0, 0);
    public bool ShowPasswordListDetails => !CompactPasswordList;
    public string NoteCountText => _localization.Format("NoteCountFormat", NoteItems.Count);
    public string TotpCountText => _localization.Format("TotpCountFormat", TotpItems.Count);
    public string WalletCountText => _localization.Format("WalletCountFormat", WalletItems.Count);
    public string TimelineCountText => _localization.Format("TimelineCountFormat", TimelineEntries.Count);
    public string SecurityIssueCountText => _localization.Format("SecurityIssueCountFormat", SecurityIssueItems.Count);
    public string GeneratorLengthText => _localization.Format("GeneratorLengthFormat", GeneratorLength);
    public string GeneratedPasswordStrengthText
    {
        get
        {
            if (string.IsNullOrWhiteSpace(GeneratedPassword))
            {
                return _localization.Get("GeneratorNoPassword");
            }

            var strength = _passwordGenerator.Analyze(GeneratedPassword);
            return _localization.Format("GeneratedPasswordStrengthFormat", strength.Label, strength.Score, string.Join(" ", strength.Warnings));
        }
    }

    public string NotePreviewMarkdown => NoteIsMarkdown ? NoteContent : "";
    public string NotePlainPreview => NoteContentCodec.ToPlainPreview(NoteContent, NoteIsMarkdown);
    public int SelectedPasswordCount => Passwords.Count(item => item.IsSelected);
    public bool HasSelectedPasswords => SelectedPasswordCount > 0;
    public bool AreAllFilteredPasswordsSelected
    {
        get
        {
            var filtered = FilteredPasswords.ToArray();
            return filtered.Length > 0 && filtered.All(item => item.IsSelected);
        }
        set
        {
            foreach (var item in FilteredPasswords)
            {
                item.IsSelected = value;
            }

            RaisePasswordSelectionState();
        }
    }

    public IEnumerable<PasswordQuickAccessItem> RecentPasswordQuickAccessItems =>
        BuildQuickAccessItems(QuickAccessSort.Recent);

    public IEnumerable<PasswordQuickAccessItem> FrequentPasswordQuickAccessItems =>
        BuildQuickAccessItems(QuickAccessSort.Frequent);

    public bool HasPasswordQuickAccessItems => RecentPasswordQuickAccessItems.Any() || FrequentPasswordQuickAccessItems.Any();

    public IEnumerable<PasswordEntry> FilteredPasswords =>
        ApplyPasswordSort(Passwords.Where(MatchesPasswordFilters));
    public IEnumerable<PasswordEntry> FilteredArchivedPasswords =>
        ArchivedPasswords.Where(item => MatchesPasswordSearch(item, SearchText));
    public IEnumerable<PasswordEntry> FilteredDeletedPasswords =>
        DeletedPasswords.Where(item => MatchesPasswordSearch(item, SearchText));

    partial void OnSearchTextChanged(string value)
    {
        OnPropertyChanged(nameof(FilteredPasswords));
        OnPropertyChanged(nameof(FilteredArchivedPasswords));
        OnPropertyChanged(nameof(FilteredDeletedPasswords));
        RaisePasswordSelectionState();
    }

    partial void OnQuickFilterFavoriteChanged(bool value) => RefreshPasswordFilters();
    partial void OnQuickFilter2FaChanged(bool value) => RefreshPasswordFilters();
    partial void OnQuickFilterNotesChanged(bool value) => RefreshPasswordFilters();
    partial void OnQuickFilterPasskeyChanged(bool value) => RefreshPasswordFilters();
    partial void OnQuickFilterBoundNoteChanged(bool value) => RefreshPasswordFilters();
    partial void OnQuickFilterUncategorizedChanged(bool value) => RefreshPasswordFilters();
    partial void OnQuickFilterLocalOnlyChanged(bool value) => RefreshPasswordFilters();
    partial void OnQuickFilterAttachmentsChanged(bool value) => RefreshPasswordFilters();
    partial void OnSelectedPasswordFolderFilterChanged(PasswordFolderFilterChoice? value)
    {
        RefreshPasswordFilters();
        OnPropertyChanged(nameof(CanManageSelectedPasswordFolder));
    }
    partial void OnSelectedPasswordSortChanged(string value)
    {
        UpdateSettings(settings => settings.PasswordSortOrder = value);
        OnPropertyChanged(nameof(FilteredPasswords));
        RaisePasswordSelectionState();
    }

    partial void OnSelectedSectionChanged(string value) => OnPropertyChanged(nameof(SelectedSectionTitle));

    partial void OnGeneratedPasswordChanged(string value) => OnPropertyChanged(nameof(GeneratedPasswordStrengthText));

    partial void OnGeneratorLengthChanged(int value)
    {
        GeneratorLength = Math.Clamp(value, 8, 128);
        OnPropertyChanged(nameof(GeneratorLengthText));
    }

    partial void OnNoteContentChanged(string value)
    {
        OnPropertyChanged(nameof(NotePreviewMarkdown));
        OnPropertyChanged(nameof(NotePlainPreview));
    }

    partial void OnNoteIsMarkdownChanged(bool value)
    {
        OnPropertyChanged(nameof(NotePreviewMarkdown));
        OnPropertyChanged(nameof(NotePlainPreview));
    }

    partial void OnSelectedNoteChanged(SecureItem? value) => LoadNoteIntoEditor(value);

    partial void OnIsVaultInitializedChanged(bool value)
    {
        OnPropertyChanged(nameof(LoginTitle));
        OnPropertyChanged(nameof(LoginDescription));
        OnPropertyChanged(nameof(LoginButtonText));
    }

    partial void OnSettingsLanguageChanged(string value)
    {
        if (_isApplyingSettings)
        {
            return;
        }

        _localization.SetLanguage(value);
        _settingsService.Current.Language = value;
        QueueSaveSettings();
    }

    partial void OnSettingsThemeChanged(string value)
    {
        ApplyTheme(value);
        UpdateSettings(settings => settings.Theme = value);
    }

    partial void OnStartupSectionChanged(string value) => UpdateSettings(settings => settings.StartupSection = value);
    partial void OnAutoLockEnabledChanged(bool value) => UpdateSettings(settings => settings.AutoLockEnabled = value);
    partial void OnAutoLockMinutesChanged(int value) => UpdateSettings(settings => settings.AutoLockMinutes = value);
    partial void OnClearClipboardEnabledChanged(bool value) => UpdateSettings(settings => settings.ClearClipboardEnabled = value);
    partial void OnClipboardClearSecondsChanged(int value) => UpdateSettings(settings => settings.ClipboardClearSeconds = value);
    partial void OnRequirePasswordBeforeExportChanged(bool value) => UpdateSettings(settings => settings.RequirePasswordBeforeExport = value);
    partial void OnMinimizeToTrayChanged(bool value) => UpdateSettings(settings => settings.MinimizeToTray = value);
    partial void OnQuickSearchEnabledChanged(bool value) => UpdateSettings(settings => settings.QuickSearchEnabled = value);
    partial void OnQuickSearchHotkeyChanged(string value) => UpdateSettings(settings => settings.QuickSearchHotkey = value);
    partial void OnBrowserIntegrationEnabledChanged(bool value) => UpdateSettings(settings => settings.BrowserIntegrationEnabled = value);
    partial void OnBrowserIntegrationPortChanged(int value) => UpdateSettings(settings => settings.BrowserIntegrationPort = value);
    partial void OnCompactPasswordListChanged(bool value)
    {
        UpdateSettings(settings => settings.CompactPasswordList = value);
        OnPropertyChanged(nameof(PasswordListCardPadding));
        OnPropertyChanged(nameof(PasswordListAvatarSize));
        OnPropertyChanged(nameof(PasswordListAvatarFontSize));
        OnPropertyChanged(nameof(PasswordListRowMinHeight));
        OnPropertyChanged(nameof(PasswordListAvatarCornerRadius));
        OnPropertyChanged(nameof(PasswordListContentMargin));
        OnPropertyChanged(nameof(ShowPasswordListDetails));
    }
    partial void OnWebDavEnabledChanged(bool value) => UpdateSettings(settings => settings.WebDavEnabled = value);
    partial void OnWebDavServerUrlChanged(string value) => UpdateSettings(settings => settings.WebDavServerUrl = value);
    partial void OnWebDavUsernameChanged(string value) => UpdateSettings(settings => settings.WebDavUsername = value);
    partial void OnWebDavRemotePathChanged(string value) => UpdateSettings(settings => settings.WebDavRemotePath = value);
    partial void OnWebDavSyncOnStartupChanged(bool value) => UpdateSettings(settings => settings.WebDavSyncOnStartup = value);
    partial void OnWebDavSyncAfterChangesChanged(bool value) => UpdateSettings(settings => settings.WebDavSyncAfterChanges = value);
    partial void OnSyncConflictStrategyChanged(string value) => UpdateSettings(settings => settings.SyncConflictStrategy = value);
    partial void OnOneDriveEnabledChanged(bool value) => UpdateSettings(settings => settings.OneDriveEnabled = value);
    partial void OnMdbxLocalCacheEnabledChanged(bool value) => UpdateSettings(settings => settings.MdbxLocalCacheEnabled = value);

    [RelayCommand]
    public async Task InitializeAsync()
    {
        try
        {
            await _settingsService.LoadAsync();
            ApplySettings(_settingsService.Current);
            IsVaultInitialized = await _credentialStore.GetAsync() is not null;
            StatusMessage = IsVaultInitialized
                ? _localization.Get("VaultLocked")
                : _localization.Get("FirstRunCreateMasterPassword");
        }
        catch (Exception ex)
        {
            StatusMessage = _localization.Format("VaultMetadataLoadFailedFormat", ex.Message);
        }
    }

    [RelayCommand]
    private async Task UnlockAsync()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(MasterPassword))
            {
                StatusMessage = _localization.Get("EnterMasterPassword");
                return;
            }

            var storedHash = await _credentialStore.GetAsync();
            if (storedHash is null)
            {
                if (MasterPassword.Length < 8)
                {
                    StatusMessage = _localization.Get("MasterPasswordMinLength");
                    return;
                }

                if (!string.Equals(MasterPassword, ConfirmMasterPassword, StringComparison.Ordinal))
                {
                    StatusMessage = _localization.Get("ConfirmationMismatch");
                    return;
                }

                storedHash = _cryptoService.HashMasterPassword(MasterPassword);
                await _credentialStore.SaveAsync(storedHash);
                IsVaultInitialized = true;
            }

            if (!_cryptoService.VerifyMasterPassword(MasterPassword, storedHash))
            {
                StatusMessage = _localization.Get("WrongMasterPassword");
                MasterPassword = "";
                ConfirmMasterPassword = "";
                return;
            }

            IsUnlocked = true;
            MasterPassword = "";
            ConfirmMasterPassword = "";
            StatusMessage = _localization.Get("VaultUnlocked");
            await LoadAsync();
        }
        catch (Exception ex)
        {
            IsUnlocked = false;
            StatusMessage = _localization.Format("UnlockFailedFormat", ex.Message);
        }
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        try
        {
            Passwords.Clear();
            ArchivedPasswords.Clear();
            DeletedPasswords.Clear();
            NoteItems.Clear();
            TotpItems.Clear();
            WalletItems.Clear();
            Categories.Clear();
            MdbxDatabases.Clear();
            TimelineEntries.Clear();

            var allPasswords = await _repository.GetPasswordsAsync(includeDeleted: true, includeArchived: true);
            var activePasswords = allPasswords.Where(item => !item.IsDeleted && !item.IsArchived).ToArray();
            var archivedPasswords = allPasswords.Where(item => !item.IsDeleted && item.IsArchived).ToArray();
            var deletedPasswords = allPasswords.Where(item => item.IsDeleted).ToArray();
            _passwordCustomFields = await _repository.GetCustomFieldsByEntryIdsAsync(allPasswords.Select(item => item.Id).ToArray());
            _passwordAttachments = await _repository.GetAttachmentsByOwnerIdsAsync("PASSWORD", allPasswords.Select(item => item.Id).ToArray());
            foreach (var item in activePasswords)
            {
                RefreshPasswordTotpDisplay(item);
                RefreshPasswordAttachmentState(item);
                item.IsSelected = false;
                TrackPasswordSelection(item);
                Passwords.Add(item);
            }

            foreach (var item in archivedPasswords)
            {
                RefreshPasswordTotpDisplay(item);
                RefreshPasswordAttachmentState(item);
                item.IsSelected = false;
                TrackPasswordSelection(item);
                ArchivedPasswords.Add(item);
            }

            foreach (var item in deletedPasswords)
            {
                RefreshPasswordTotpDisplay(item);
                RefreshPasswordAttachmentState(item);
                item.IsSelected = false;
                TrackPasswordSelection(item);
                DeletedPasswords.Add(item);
            }

            foreach (var item in await _repository.GetSecureItemsAsync(VaultItemType.Note))
            {
                NoteItems.Add(item);
            }

            foreach (var item in await _repository.GetSecureItemsAsync())
            {
                if (item.ItemType is VaultItemType.BankCard or VaultItemType.Document)
                {
                    WalletItems.Add(item);
                }
            }

            foreach (var category in await _repository.GetCategoriesAsync())
            {
                Categories.Add(category);
            }

            RefreshPasswordFolderFilters();
            await LoadPasswordQuickAccessAsync();
            foreach (var database in await _repository.GetMdbxDatabasesAsync())
            {
                MdbxDatabases.Add(database);
            }

            await LoadTotpItemsAsync();
            await LoadTimelineAsync();
            RefreshSecurityAnalysis();
            RaiseCounts();
            OnPropertyChanged(nameof(FilteredPasswords));
        }
        catch (Exception ex)
        {
            IsUnlocked = false;
            StatusMessage = _localization.Format("VaultLoadFailedFormat", ex.Message);
        }
    }

    [RelayCommand]
    private void SelectSection(string? section)
    {
        if (!string.IsNullOrWhiteSpace(section))
        {
            SelectedSection = section;
        }
    }

    [RelayCommand]
    private async Task AddPasswordAsync()
    {
        var initialPassword = string.IsNullOrWhiteSpace(GeneratedPassword) ? "" : GeneratedPassword;
        var editor = await _passwordEditorDialogService.ShowAsync(
            null,
            Categories.ToList(),
            initialPassword,
            notes: NoteItems.ToList());
        if (editor is null)
        {
            return;
        }

        var entries = editor
            .BuildEntries(ProtectPasswords(editor.GetPasswordRows()))
            .ToList();
        foreach (var entry in entries)
        {
            await _repository.SavePasswordAsync(entry);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = entry.Id,
                ItemTitle = entry.Title,
                OperationType = "CREATE",
                DeviceName = Environment.MachineName
            });
        }

        var customFields = BindCustomFields(entries[0].Id, editor.GetCustomFields());
        await _repository.ReplaceCustomFieldsAsync(entries[0].Id, customFields);
        SetPasswordCustomFields(entries[0].Id, customFields);
        foreach (var entry in entries)
        {
            RefreshPasswordTotpDisplay(entry);
        }

        await SynchronizeBoundTotpAsync(entries[0]);
        ReplacePasswordGroup([], entries);
        await LoadTotpItemsAsync();
        await LoadTimelineAsync();
        RefreshSecurityAnalysis();
        RaiseCounts();
        OnPropertyChanged(nameof(FilteredPasswords));
        StatusMessage = _localization.Format("CreatedPasswordFormat", entries[0].Title);
    }

    [RelayCommand]
    private async Task EditPasswordAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var siblings = GetPasswordSiblings(entry).ToList();
        var customFields = await GetGroupCustomFieldsAsync(entry, siblings);
        var editor = await _passwordEditorDialogService.ShowAsync(
            entry,
            Categories.ToList(),
            UnprotectPassword(entry.Password),
            siblings.Select(item => UnprotectPassword(item.Password)).ToArray(),
            NoteItems.ToList(),
            customFields);
        if (editor is null)
        {
            return;
        }

        var passwordRows = editor.GetPasswordRows();
        var storedPasswords = ProtectPasswords(passwordRows);
        var updatedEntries = new List<PasswordEntry>();
        for (var index = 0; index < storedPasswords.Count; index++)
        {
            var source = index < siblings.Count ? siblings[index] : null;
            var oldPlainPassword = source is null ? "" : UnprotectPassword(source.Password);
            var updated = editor.BuildEntryFrom(source, storedPasswords[index]);
            await _repository.SavePasswordAsync(updated);
            await SavePasswordHistorySnapshotIfChangedAsync(updated.Id, oldPlainPassword, passwordRows[index]);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = updated.Id,
                ItemTitle = updated.Title,
                OperationType = source is null ? "CREATE" : "UPDATE",
                DeviceName = Environment.MachineName
            });
            updatedEntries.Add(updated);
        }

        foreach (var removed in siblings.Skip(storedPasswords.Count))
        {
            await _repository.SoftDeletePasswordAsync(removed.Id);
        }

        var updatedCustomFields = BindCustomFields(updatedEntries[0].Id, editor.GetCustomFields());
        await _repository.ReplaceCustomFieldsAsync(updatedEntries[0].Id, updatedCustomFields);
        SetPasswordCustomFields(updatedEntries[0].Id, updatedCustomFields);
        foreach (var updated in updatedEntries)
        {
            RefreshPasswordTotpDisplay(updated);
        }

        await SynchronizeBoundTotpAsync(updatedEntries[0]);
        ReplacePasswordGroup(siblings, updatedEntries);
        await LoadTotpItemsAsync();
        await LoadTimelineAsync();
        RefreshSecurityAnalysis();
        RaiseCounts();
        OnPropertyChanged(nameof(FilteredPasswords));
        StatusMessage = _localization.Format("UpdatedPasswordFormat", updatedEntries[0].Title);
    }

    [RelayCommand]
    private async Task CopyPasswordAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var text = entry.Password;
        if (_cryptoService.IsUnlocked)
        {
            try
            {
                text = _cryptoService.DecryptString(entry.Password);
            }
            catch
            {
                text = entry.Password;
            }
        }

        await _clipboardService.SetTextAsync(text);
        StatusMessage = _localization.Format("CopiedPasswordFormat", entry.Title);
    }

    [RelayCommand]
    private async Task CopyUsernameAsync(PasswordEntry? entry)
    {
        if (entry is null || string.IsNullOrWhiteSpace(entry.Username))
        {
            return;
        }

        await _clipboardService.SetTextAsync(entry.Username);
        StatusMessage = _localization.Format("CopiedUsernameFormat", entry.Title);
    }

    [RelayCommand]
    private async Task CopyWebsiteAsync(PasswordEntry? entry)
    {
        if (entry is null || string.IsNullOrWhiteSpace(entry.Website))
        {
            return;
        }

        await _clipboardService.SetTextAsync(entry.Website);
        StatusMessage = _localization.Format("CopiedWebsiteFormat", entry.Title);
    }

    [RelayCommand]
    private async Task ShowPasswordDetailsAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        await RecordPasswordQuickAccessAsync(entry);
        var siblings = entry.IsDeleted
            ? GetDeletedPasswordSiblings(entry).ToList()
            : entry.IsArchived
                ? GetArchivedPasswordSiblings(entry).ToList()
                : GetPasswordSiblings(entry).ToList();
        var customFields = await GetGroupCustomFieldsAsync(entry, siblings);
        var category = entry.CategoryId is null
            ? null
            : Categories.FirstOrDefault(item => item.Id == entry.CategoryId);
        var boundNote = entry.BoundNoteId is null
            ? null
            : NoteItems.FirstOrDefault(item => item.Id == entry.BoundNoteId);
        var attachments = GetGroupAttachments(entry, siblings);
        var history = await GetPasswordHistoryDisplayItemsAsync(entry.Id);

        await _passwordDetailDialogService.ShowAsync(
            entry,
            siblings,
            category,
            boundNote,
            attachments,
            customFields,
            history,
            AddPasswordAttachmentAsync,
            DeletePasswordAttachmentAsync,
            DeletePasswordHistoryAsync,
            ClearPasswordHistoryAsync);
    }

    [RelayCommand]
    private async Task OpenQuickAccessPasswordAsync(PasswordQuickAccessItem? item)
    {
        if (item is null)
        {
            return;
        }

        await ShowPasswordDetailsAsync(item.Entry);
    }

    [RelayCommand]
    private void TogglePasswordSelection(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        entry.IsSelected = !entry.IsSelected;
        RaisePasswordSelectionState();
    }

    [RelayCommand]
    private void ClearPasswordSelection()
    {
        foreach (var entry in Passwords.Where(item => item.IsSelected))
        {
            entry.IsSelected = false;
        }

        RaisePasswordSelectionState();
    }

    [RelayCommand]
    private async Task FavoriteSelectedPasswordsAsync()
    {
        var selected = Passwords.Where(item => item.IsSelected).ToArray();
        foreach (var entry in selected)
        {
            if (!entry.IsFavorite)
            {
                entry.IsFavorite = true;
                await _repository.SavePasswordAsync(entry);
                await _repository.LogAsync(new OperationLog
                {
                    ItemType = "PASSWORD",
                    ItemId = entry.Id,
                    ItemTitle = entry.Title,
                    OperationType = "FAVORITE",
                    DeviceName = Environment.MachineName
                });
            }
        }

        foreach (var entry in selected)
        {
            entry.IsSelected = false;
        }

        RaisePasswordSelectionState();
        OnPropertyChanged(nameof(FilteredPasswords));
        RefreshSecurityAnalysis();
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("FavoritedPasswordCountFormat", selected.Length);
    }

    [RelayCommand]
    private async Task DeleteSelectedPasswordsAsync()
    {
        var selected = Passwords.Where(item => item.IsSelected).ToArray();
        var handled = new HashSet<long>();
        foreach (var entry in selected)
        {
            if (!handled.Add(entry.Id))
            {
                continue;
            }

            var siblings = GetPasswordSiblings(entry).ToArray();
            foreach (var sibling in siblings)
            {
                handled.Add(sibling.Id);
            }

            await DeletePasswordGroupAsync(entry, siblings, updateStatus: false);
        }

        RaisePasswordSelectionState();
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("MovedSelectedPasswordsToRecycleBinFormat", selected.Length);
    }

    [RelayCommand]
    private async Task ArchiveSelectedPasswordsAsync()
    {
        var selected = Passwords.Where(item => item.IsSelected).ToArray();
        if (selected.Length == 0)
        {
            return;
        }

        var handled = new HashSet<long>();
        foreach (var entry in selected)
        {
            if (!handled.Add(entry.Id))
            {
                continue;
            }

            var siblings = GetPasswordSiblings(entry).ToArray();
            foreach (var sibling in siblings)
            {
                handled.Add(sibling.Id);
            }

            await ArchivePasswordGroupAsync(entry, siblings, updateStatus: false);
        }

        RaisePasswordSelectionState();
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("ArchivedSelectedPasswordsFormat", selected.Length);
    }

    [RelayCommand]
    private async Task MoveSelectedPasswordsToCategoryAsync()
    {
        var selected = Passwords.Where(item => item.IsSelected).ToArray();
        if (selected.Length == 0)
        {
            return;
        }

        var currentCategoryId = selected
            .Select(item => item.CategoryId)
            .Distinct()
            .Count() == 1
                ? selected[0].CategoryId
                : null;
        var choice = await _categoryPickerDialogService.ShowAsync(Categories.ToList(), currentCategoryId);
        if (choice is null)
        {
            return;
        }

        var handled = new HashSet<long>();
        foreach (var entry in selected)
        {
            if (!handled.Add(entry.Id))
            {
                continue;
            }

            var siblings = GetPasswordSiblings(entry).ToArray();
            foreach (var sibling in siblings)
            {
                handled.Add(sibling.Id);
                sibling.CategoryId = choice.Id;
                await _repository.SavePasswordAsync(sibling);
                await SynchronizeBoundTotpAsync(sibling);
                await _repository.LogAsync(new OperationLog
                {
                    ItemType = "PASSWORD",
                    ItemId = sibling.Id,
                    ItemTitle = sibling.Title,
                    OperationType = "MOVE_CATEGORY",
                    DeviceName = Environment.MachineName
                });
            }
        }

        foreach (var entry in selected)
        {
            entry.IsSelected = false;
        }

        await LoadTotpItemsAsync();
        RaisePasswordSelectionState();
        RefreshPasswordFolderFilters(choice.Id);
        OnPropertyChanged(nameof(FilteredPasswords));
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("MovedSelectedPasswordsToFolderFormat", selected.Length, choice.Name);
    }

    [RelayCommand]
    private async Task StackSelectedPasswordsAsync()
    {
        var selected = Passwords
            .Where(item => item.IsSelected)
            .OrderBy(item => item.Id == 0 ? long.MaxValue : item.Id)
            .ToArray();
        if (selected.Length < 2)
        {
            return;
        }

        var replicaGroupId = selected
            .Select(item => item.ReplicaGroupId)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))
            ?? $"manual-{Guid.NewGuid():N}";
        foreach (var entry in selected)
        {
            entry.ReplicaGroupId = replicaGroupId;
            entry.IsSelected = false;
            await _repository.SavePasswordAsync(entry);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = entry.Id,
                ItemTitle = entry.Title,
                OperationType = "STACK",
                DeviceName = Environment.MachineName
            });
        }

        RaisePasswordSelectionState();
        OnPropertyChanged(nameof(FilteredPasswords));
        RefreshSecurityAnalysis();
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("StackedPasswordCountFormat", selected.Length);
    }

    [RelayCommand]
    private async Task CopyPasswordTotpAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        RefreshPasswordTotpDisplay(entry);
        await _clipboardService.SetTextAsync(entry.TotpCode);
        StatusMessage = _localization.Format("CopiedTotpFormat", entry.Title);
    }

    [RelayCommand]
    private async Task ToggleFavoriteAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        entry.IsFavorite = !entry.IsFavorite;
        await _repository.SavePasswordAsync(entry);
        await _repository.LogAsync(new OperationLog
        {
            ItemType = "PASSWORD",
            ItemId = entry.Id,
            ItemTitle = entry.Title,
            OperationType = "FAVORITE",
            DeviceName = Environment.MachineName
        });
        await LoadTimelineAsync();
        RefreshSecurityAnalysis();
        OnPropertyChanged(nameof(FilteredPasswords));
    }

    [RelayCommand]
    private async Task DeletePasswordAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var siblings = entry.IsArchived
            ? GetArchivedPasswordSiblings(entry).ToList()
            : GetPasswordSiblings(entry).ToList();
        await DeletePasswordGroupAsync(entry, siblings, updateStatus: true);
    }

    [RelayCommand]
    private async Task ArchivePasswordAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var siblings = GetPasswordSiblings(entry).ToList();
        await ArchivePasswordGroupAsync(entry, siblings, updateStatus: true);
    }

    private async Task ArchivePasswordGroupAsync(PasswordEntry entry, IReadOnlyList<PasswordEntry> siblings, bool updateStatus)
    {
        foreach (var item in siblings)
        {
            item.IsArchived = true;
            item.ArchivedAt = DateTimeOffset.UtcNow;
            item.IsSelected = false;
            await _repository.SavePasswordAsync(item);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = item.Id,
                ItemTitle = item.Title,
                OperationType = "ARCHIVE",
                DeviceName = Environment.MachineName
            });
            Passwords.Remove(item);
            var current = Passwords.FirstOrDefault(password => password.Id == item.Id);
            if (current is not null)
            {
                current.IsSelected = false;
                Passwords.Remove(current);
            }

            TrackPasswordSelection(item);
            ArchivedPasswords.Insert(0, item);
        }

        await LoadTotpItemsAsync();
        RaiseCounts();
        RaisePasswordSelectionState();
        OnPropertyChanged(nameof(FilteredPasswords));
        RefreshSecurityAnalysis();
        await LoadTimelineAsync();
        if (updateStatus)
        {
            StatusMessage = _localization.Format("ArchivedPasswordFormat", entry.Title);
        }
    }

    [RelayCommand]
    private async Task UnarchivePasswordAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var siblings = GetArchivedPasswordSiblings(entry).ToList();
        foreach (var item in siblings)
        {
            item.IsArchived = false;
            item.ArchivedAt = null;
            item.IsSelected = false;
            await _repository.SavePasswordAsync(item);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = item.Id,
                ItemTitle = item.Title,
                OperationType = "UNARCHIVE",
                DeviceName = Environment.MachineName
            });
            ArchivedPasswords.Remove(item);
            var current = ArchivedPasswords.FirstOrDefault(password => password.Id == item.Id);
            if (current is not null)
            {
                ArchivedPasswords.Remove(current);
            }

            RefreshPasswordTotpDisplay(item);
            RefreshPasswordAttachmentState(item);
        }

        ReplacePasswordGroup([], siblings);
        await LoadTotpItemsAsync();
        await LoadTimelineAsync();
        RaiseCounts();
        OnPropertyChanged(nameof(FilteredPasswords));
        RefreshSecurityAnalysis();
        StatusMessage = _localization.Format("UnarchivedPasswordFormat", entry.Title);
    }

    private async Task DeletePasswordGroupAsync(PasswordEntry entry, IReadOnlyList<PasswordEntry> siblings, bool updateStatus)
    {
        foreach (var item in siblings)
        {
            await _repository.SoftDeletePasswordAsync(item.Id);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = item.Id,
                ItemTitle = item.Title,
                OperationType = "DELETE",
                DeviceName = Environment.MachineName
            });
            item.IsSelected = false;
            Passwords.Remove(item);
            var current = Passwords.FirstOrDefault(password => password.Id == item.Id);
            if (current is not null)
            {
                current.IsSelected = false;
                Passwords.Remove(current);
            }

            ArchivedPasswords.Remove(item);
            var archived = ArchivedPasswords.FirstOrDefault(password => password.Id == item.Id);
            if (archived is not null)
            {
                archived.IsSelected = false;
                ArchivedPasswords.Remove(archived);
            }

            item.IsDeleted = true;
            item.DeletedAt = DateTimeOffset.UtcNow;
            item.IsArchived = false;
            item.ArchivedAt = null;
            TrackPasswordSelection(item);
            DeletedPasswords.Insert(0, item);
        }

        await LoadTotpItemsAsync();
        RaiseCounts();
        RaisePasswordSelectionState();
        OnPropertyChanged(nameof(FilteredPasswords));
        RefreshSecurityAnalysis();
        await LoadTimelineAsync();
        if (updateStatus)
        {
            StatusMessage = _localization.Format("MovedToRecycleBinFormat", entry.Title);
        }
    }

    [RelayCommand]
    private async Task RestorePasswordAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var siblings = GetDeletedPasswordSiblings(entry).ToList();
        foreach (var item in siblings)
        {
            await _repository.RestorePasswordAsync(item.Id);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = item.Id,
                ItemTitle = item.Title,
                OperationType = "RESTORE",
                DeviceName = Environment.MachineName
            });
            DeletedPasswords.Remove(item);
            var current = DeletedPasswords.FirstOrDefault(password => password.Id == item.Id);
            if (current is not null)
            {
                DeletedPasswords.Remove(current);
            }

            item.IsDeleted = false;
            item.DeletedAt = null;
            item.IsSelected = false;
            RefreshPasswordTotpDisplay(item);
        }

        ReplacePasswordGroup([], siblings);
        await LoadTotpItemsAsync();
        await LoadTimelineAsync();
        RaiseCounts();
        OnPropertyChanged(nameof(FilteredPasswords));
        RefreshSecurityAnalysis();
        StatusMessage = _localization.Format("RestoredPasswordFormat", entry.Title);
    }

    [RelayCommand]
    private async Task DeletePasswordPermanentlyAsync(PasswordEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var siblings = GetDeletedPasswordSiblings(entry).ToList();
        foreach (var item in siblings)
        {
            await _repository.DeletePasswordPermanentlyAsync(item.Id);
            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemId = item.Id,
                ItemTitle = item.Title,
                OperationType = "PURGE",
                DeviceName = Environment.MachineName
            });
            DeletedPasswords.Remove(item);
            var current = DeletedPasswords.FirstOrDefault(password => password.Id == item.Id);
            if (current is not null)
            {
                DeletedPasswords.Remove(current);
            }
        }

        await LoadTotpItemsAsync();
        await LoadTimelineAsync();
        RaiseCounts();
        RefreshSecurityAnalysis();
        StatusMessage = _localization.Format("DeletedPasswordPermanentlyFormat", entry.Title);
    }

    [RelayCommand]
    private async Task AddTotpAsync()
    {
        var item = new SecureItem
        {
            ItemType = VaultItemType.Totp,
            Title = $"Authenticator {TotpItems.Count + 1}",
            Notes = "Monica desktop sample",
            ItemData = """{"secret":"JBSWY3DPEHPK3PXP","period":30,"digits":6,"otpType":"TOTP"}"""
        };
        RefreshTotpDisplay(item);
        await _repository.SaveSecureItemAsync(item);
        TotpItems.Insert(0, item);
        RaiseCounts();
    }

    [RelayCommand]
    private async Task CopyTotpAsync(SecureItem? item)
    {
        if (item is null)
        {
            return;
        }

        RefreshTotpDisplay(item);
        await _clipboardService.SetTextAsync(item.TotpCode);
        StatusMessage = _localization.Format("CopiedTotpFormat", item.Title);
    }

    [RelayCommand]
    private async Task AddWalletItemAsync()
    {
        var item = new SecureItem
        {
            ItemType = WalletItems.Count % 2 == 0 ? VaultItemType.BankCard : VaultItemType.Document,
            Title = WalletItems.Count % 2 == 0 ? "Bank Card" : "Identity Document",
            Notes = "Desktop wallet entry",
            ItemData = "{}"
        };
        await _repository.SaveSecureItemAsync(item);
        WalletItems.Insert(0, item);
        RaiseCounts();
    }

    public async Task<long> AddPasswordAttachmentMetadataAsync(
        PasswordEntry entry,
        string fileName,
        string storagePath,
        long sizeBytes = 0,
        string contentType = "",
        CancellationToken cancellationToken = default)
    {
        if (entry.Id == 0)
        {
            throw new ArgumentException("Password entry must be saved before adding attachments.", nameof(entry));
        }

        var attachment = new Attachment
        {
            OwnerType = "PASSWORD",
            OwnerId = entry.Id,
            FileName = string.IsNullOrWhiteSpace(fileName) ? _localization.Get("Attachment") : fileName.Trim(),
            ContentType = contentType.Trim(),
            StoragePath = storagePath.Trim(),
            SizeBytes = Math.Max(0, sizeBytes),
            CreatedAt = DateTimeOffset.UtcNow,
            BitwardenVaultId = entry.BitwardenVaultId
        };

        var id = await _repository.SaveAttachmentAsync(attachment, cancellationToken);
        SetPasswordAttachments(entry.Id, [.. GetPasswordAttachments(entry.Id), attachment]);
        RefreshPasswordAttachmentState(entry);
        OnPropertyChanged(nameof(FilteredPasswords));
        await _repository.LogAsync(new OperationLog
        {
            ItemType = "PASSWORD",
            ItemId = entry.Id,
            ItemTitle = entry.Title,
            OperationType = "ATTACHMENT",
            DeviceName = Environment.MachineName
        }, cancellationToken);
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("AddedAttachmentFormat", attachment.FileName, entry.Title);
        return id;
    }

    [RelayCommand]
    private async Task AddPasswordAttachmentAsync(PasswordEntry? entry)
    {
        if (entry is null || entry.Id <= 0 || entry.IsDeleted)
        {
            return;
        }

        var draft = await _passwordAttachmentFileService.PickAndStoreAttachmentAsync(entry);
        if (draft is null)
        {
            return;
        }

        await AddPasswordAttachmentMetadataAsync(entry, draft.FileName, draft.StoragePath, draft.SizeBytes, draft.ContentType);
    }

    private async Task DeletePasswordAttachmentAsync(Attachment attachment)
    {
        await _repository.DeleteAttachmentAsync(attachment.Id);
        await _passwordAttachmentFileService.DeleteStoredAttachmentAsync(attachment.StoragePath);
        var remaining = GetPasswordAttachments(attachment.OwnerId)
            .Where(item => item.Id != attachment.Id)
            .ToArray();
        SetPasswordAttachments(attachment.OwnerId, remaining);

        var entry = Passwords
            .Concat(ArchivedPasswords)
            .Concat(DeletedPasswords)
            .FirstOrDefault(item => item.Id == attachment.OwnerId);
        if (entry is not null)
        {
            RefreshPasswordAttachmentState(entry);
            OnPropertyChanged(nameof(FilteredPasswords));
        }

        StatusMessage = _localization.Format("DeletedAttachmentFormat", attachment.FileName);
    }

    [RelayCommand]
    private void AddNote()
    {
        SelectedNote = null;
        NoteTitle = "";
        NoteContent = "";
        NoteTagsText = "";
        NoteIsMarkdown = true;
        NotePreviewMode = false;
        NoteIsFavorite = false;
        StatusMessage = _localization.Get("EditingNewSecureNote");
    }

    [RelayCommand]
    private async Task SaveNoteAsync()
    {
        if (string.IsNullOrWhiteSpace(NoteTitle) && string.IsNullOrWhiteSpace(NoteContent))
        {
            StatusMessage = _localization.Get("NoteRequiresContent");
            return;
        }

        var payload = NoteContentCodec.BuildSavePayload(
            NoteTitle,
            NoteContent,
            NoteTagsText,
            NoteIsMarkdown,
            SelectedNote is null ? [] : NoteContentCodec.DecodeImagePaths(SelectedNote.ImagePaths));

        var item = SelectedNote ?? new SecureItem
        {
            ItemType = VaultItemType.Note,
            CreatedAt = DateTimeOffset.UtcNow
        };

        item.Title = payload.Title;
        item.Notes = payload.NotesCache;
        item.ItemData = payload.ItemData;
        item.ImagePaths = payload.ImagePaths;
        item.IsFavorite = NoteIsFavorite;
        item.ItemType = VaultItemType.Note;
        item.SyncStatus = item.BitwardenVaultId is null ? SyncStatus.None : SyncStatus.Pending;

        await _repository.SaveSecureItemAsync(item);
        await _repository.LogAsync(new OperationLog
        {
            ItemType = "NOTE",
            ItemId = item.Id,
            ItemTitle = item.Title,
            OperationType = SelectedNote is null ? "CREATE" : "UPDATE",
            DeviceName = Environment.MachineName
        });

        if (!NoteItems.Contains(item))
        {
            NoteItems.Insert(0, item);
        }

        SelectedNote = item;
        await LoadTimelineAsync();
        RaiseCounts();
        StatusMessage = _localization.Format("SavedNoteFormat", item.Title);
    }

    [RelayCommand]
    private async Task ToggleNoteFavoriteAsync()
    {
        NoteIsFavorite = !NoteIsFavorite;
        if (SelectedNote is null)
        {
            return;
        }

        SelectedNote.IsFavorite = NoteIsFavorite;
        await _repository.SaveSecureItemAsync(SelectedNote);
        StatusMessage = _localization.Format("SavedNoteFormat", SelectedNote.Title);
    }

    [RelayCommand]
    private async Task DeleteNoteAsync(SecureItem? item)
    {
        item ??= SelectedNote;
        if (item is null)
        {
            return;
        }

        await _repository.SoftDeleteSecureItemAsync(item.Id);
        NoteItems.Remove(item);
        if (ReferenceEquals(SelectedNote, item) || SelectedNote?.Id == item.Id)
        {
            AddNote();
        }

        RaiseCounts();
        StatusMessage = _localization.Format("MovedToRecycleBinFormat", item.Title);
    }

    [RelayCommand]
    private void GeneratePassword()
    {
        GeneratedPassword = _passwordGenerator.GeneratePassword(
            GeneratorLength,
            GeneratorIncludeUppercase,
            GeneratorIncludeLowercase,
            GeneratorIncludeNumbers,
            GeneratorIncludeSymbols);
        StatusMessage = _localization.Get("GeneratedPassword");
    }

    [RelayCommand]
    private async Task CopyGeneratedPasswordAsync()
    {
        if (string.IsNullOrWhiteSpace(GeneratedPassword))
        {
            GeneratePassword();
        }

        await _clipboardService.SetTextAsync(GeneratedPassword);
        StatusMessage = _localization.Get("CopiedGeneratedPassword");
    }

    [RelayCommand]
    private void ExportData()
    {
        var exportPasswords = Passwords.Select(ClonePasswordForExport).ToArray();
        var exportSecureItems = TotpItems
            .Concat(WalletItems)
            .Concat(NoteItems)
            .Where(item => item.Id > 0)
            .Select(CloneSecureItemForExport)
            .ToArray();
        ExportPreview = _importExportService.ExportJson(exportPasswords, exportSecureItems);
        StatusMessage = _localization.Get("ExportPrepared");
    }

    [RelayCommand]
    private void ExportPasswordCsv()
    {
        var exportPasswords = Passwords.Select(ClonePasswordForExport).ToArray();
        ExportCsvPreview = _importExportService.ExportPasswordCsv(exportPasswords);
        StatusMessage = _localization.Get("ExportedPasswordCsv");
    }

    [RelayCommand]
    private async Task ImportDataAsync()
    {
        if (string.IsNullOrWhiteSpace(ImportJsonText))
        {
            StatusMessage = _localization.Get("ImportJsonRequired");
            return;
        }

        try
        {
            var package = _importExportService.ImportJson(ImportJsonText);
            var passwordIdMap = new Dictionary<long, long>();
            var importedPasswords = 0;
            foreach (var source in package.Passwords)
            {
                var imported = ClonePasswordForImport(source);
                var sourceId = source.Id;
                await _repository.SavePasswordAsync(imported);
                if (sourceId != 0)
                {
                    passwordIdMap[sourceId] = imported.Id;
                }

                importedPasswords++;
            }

            var importedSecureItems = 0;
            foreach (var source in package.SecureItems)
            {
                var imported = CloneSecureItemForImport(source, passwordIdMap);
                await _repository.SaveSecureItemAsync(imported);
                importedSecureItems++;
            }

            await _repository.LogAsync(new OperationLog
            {
                ItemType = "VAULT",
                ItemTitle = _localization.Get("MonicaJson"),
                OperationType = "IMPORT",
                DeviceName = Environment.MachineName
            });

            ImportJsonText = "";
            await LoadAsync();
            StatusMessage = _localization.Format("ImportedMonicaJsonFormat", importedPasswords, importedSecureItems);
        }
        catch (Exception ex)
        {
            StatusMessage = _localization.Format("ImportFailedFormat", ex.Message);
        }
    }

    [RelayCommand]
    private async Task ImportPasswordCsvAsync()
    {
        if (string.IsNullOrWhiteSpace(ImportCsvText))
        {
            StatusMessage = _localization.Get("ImportCsvRequired");
            return;
        }

        try
        {
            var entries = _importExportService.ImportPasswordCsv(ImportCsvText);
            var importedPasswords = 0;
            foreach (var source in entries)
            {
                var imported = ClonePasswordForImport(source);
                await _repository.SavePasswordAsync(imported);
                importedPasswords++;
            }

            await _repository.LogAsync(new OperationLog
            {
                ItemType = "PASSWORD",
                ItemTitle = _localization.Get("PasswordCsv"),
                OperationType = "IMPORT",
                DeviceName = Environment.MachineName
            });

            ImportCsvText = "";
            await LoadAsync();
            StatusMessage = _localization.Format("ImportedPasswordCsvFormat", importedPasswords);
        }
        catch (Exception ex)
        {
            StatusMessage = _localization.Format("ImportFailedFormat", ex.Message);
        }
    }

    [RelayCommand]
    private async Task CreateMdbxVaultAsync()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Monica", "mdbx");
        var metadata = await _mdbxVaultService.CreateLocalMetadataAsync("Local Monica Vault", Path.Combine(root, "local.mdbx"));
        await _repository.SaveMdbxDatabaseAsync(metadata);
        MdbxDatabases.Add(metadata);
        StatusMessage = _localization.Get("CreatedMdbxMetadata");
    }

    [RelayCommand]
    private async Task CreatePasswordFolderAsync()
    {
        var name = NewFolderName.Trim();
        if (string.IsNullOrWhiteSpace(name))
        {
            StatusMessage = _localization.Get("FolderNameRequired");
            return;
        }

        var existing = Categories.FirstOrDefault(item => item.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            SelectedPasswordFolderFilter = PasswordFolderFilters.FirstOrDefault(item => item.Id == existing.Id);
            NewFolderName = "";
            StatusMessage = _localization.Format("SelectedFolderFormat", existing.Name);
            return;
        }

        var category = new Category
        {
            Name = name,
            SortOrder = Categories.Count == 0 ? 1 : Categories.Max(item => item.SortOrder) + 1
        };
        await _repository.SaveCategoryAsync(category);
        Categories.Add(category);
        RefreshPasswordFolderFilters(category.Id);
        NewFolderName = "";
        StatusMessage = _localization.Format("CreatedFolderFormat", category.Name);
    }

    [RelayCommand]
    private async Task RenameSelectedPasswordFolderAsync()
    {
        var category = GetSelectedPasswordFolderCategory();
        var name = NewFolderName.Trim();
        if (category is null)
        {
            StatusMessage = _localization.Get("SelectFolderToManage");
            return;
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            StatusMessage = _localization.Get("FolderNameRequired");
            return;
        }

        var duplicate = Categories.FirstOrDefault(item =>
            item.Id != category.Id &&
            item.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (duplicate is not null)
        {
            StatusMessage = _localization.Format("FolderAlreadyExistsFormat", duplicate.Name);
            return;
        }

        var oldName = category.Name;
        category.Name = name;
        await _repository.SaveCategoryAsync(category);
        RefreshPasswordFolderFilters(category.Id);
        NewFolderName = "";
        await _repository.LogAsync(new OperationLog
        {
            ItemType = "CATEGORY",
            ItemId = category.Id,
            ItemTitle = category.Name,
            OperationType = "UPDATE",
            DeviceName = Environment.MachineName
        });
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("RenamedFolderFormat", oldName, category.Name);
    }

    [RelayCommand]
    private async Task DeleteSelectedPasswordFolderAsync()
    {
        var category = GetSelectedPasswordFolderCategory();
        if (category is null)
        {
            StatusMessage = _localization.Get("SelectFolderToManage");
            return;
        }

        var movedPasswords = Passwords.Count(item => item.CategoryId == category.Id);
        var name = category.Name;
        await _repository.DeleteCategoryAsync(category.Id);
        Categories.Remove(category);
        foreach (var password in Passwords.Where(item => item.CategoryId == category.Id))
        {
            password.CategoryId = null;
        }

        foreach (var item in TotpItems.Where(item => item.CategoryId == category.Id))
        {
            item.CategoryId = null;
        }

        foreach (var item in NoteItems.Where(item => item.CategoryId == category.Id))
        {
            item.CategoryId = null;
        }

        foreach (var item in WalletItems.Where(item => item.CategoryId == category.Id))
        {
            item.CategoryId = null;
        }

        await _repository.LogAsync(new OperationLog
        {
            ItemType = "CATEGORY",
            ItemId = category.Id,
            ItemTitle = name,
            OperationType = "DELETE",
            DeviceName = Environment.MachineName
        });
        RefreshPasswordFolderFilters(-1);
        await LoadTimelineAsync();
        StatusMessage = _localization.Format("DeletedFolderFormat", name, movedPasswords);
    }

    public void RefreshTotpDisplay(SecureItem item)
    {
        var data = TotpDataResolver.ParseStoredItemData(item.ItemData, item.Title, item.Notes);
        if (data is null || string.IsNullOrWhiteSpace(data.Secret))
        {
            item.TotpCode = "------";
            item.TotpTimeRemaining = "";
            item.TotpProgress = 0;
            return;
        }

        item.TotpCode = _totpService.GenerateCode(data.Secret, data.Period, data.Digits, data.OtpType, data.Counter);
        item.TotpTimeRemaining = $"{_totpService.GetRemainingSeconds(data.Period)}s";
        item.TotpProgress = _totpService.GetProgress(data.Period);
    }

    private void RaiseCounts()
    {
        OnPropertyChanged(nameof(PasswordCountText));
        OnPropertyChanged(nameof(ArchivedPasswordCountText));
        OnPropertyChanged(nameof(DeletedPasswordCountText));
        OnPropertyChanged(nameof(NoteCountText));
        OnPropertyChanged(nameof(TotpCountText));
        OnPropertyChanged(nameof(WalletCountText));
        OnPropertyChanged(nameof(TimelineCountText));
        OnPropertyChanged(nameof(SecurityIssueCountText));
    }

    private void RaisePasswordSelectionState()
    {
        OnPropertyChanged(nameof(SelectedPasswordCount));
        OnPropertyChanged(nameof(SelectedPasswordCountText));
        OnPropertyChanged(nameof(HasSelectedPasswords));
        OnPropertyChanged(nameof(CanStackSelectedPasswords));
        OnPropertyChanged(nameof(AreAllFilteredPasswordsSelected));
    }

    private void RefreshPasswordFilters()
    {
        OnPropertyChanged(nameof(FilteredPasswords));
        OnPropertyChanged(nameof(FilteredArchivedPasswords));
        OnPropertyChanged(nameof(FilteredDeletedPasswords));
        RaisePasswordSelectionState();
        RefreshPasswordFolderFilters();
    }

    private void TrackPasswordSelection(PasswordEntry entry)
    {
        entry.PropertyChanged -= PasswordEntryPropertyChanged;
        entry.PropertyChanged += PasswordEntryPropertyChanged;
    }

    private void PasswordEntryPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PasswordEntry.IsSelected))
        {
            RaisePasswordSelectionState();
        }
    }

    private async Task LoadPasswordQuickAccessAsync()
    {
        _passwordQuickAccessRecords = (await _repository.GetPasswordQuickAccessRecordsAsync())
            .Where(record => record.OpenCount > 0 && record.PasswordId > 0)
            .ToDictionary(record => record.PasswordId);
        RaisePasswordQuickAccessState();
    }

    private async Task RecordPasswordQuickAccessAsync(PasswordEntry entry)
    {
        if (entry.Id <= 0 || entry.IsDeleted || entry.IsArchived)
        {
            return;
        }

        await _repository.RecordPasswordQuickAccessAsync(entry.Id);
        var next = _passwordQuickAccessRecords.ToDictionary(pair => pair.Key, pair => pair.Value);
        if (next.TryGetValue(entry.Id, out var existing))
        {
            existing.OpenCount++;
            existing.LastOpenedAt = DateTimeOffset.UtcNow;
        }
        else
        {
            next[entry.Id] = new PasswordQuickAccessRecord
            {
                PasswordId = entry.Id,
                OpenCount = 1,
                LastOpenedAt = DateTimeOffset.UtcNow
            };
        }

        _passwordQuickAccessRecords = next;
        RaisePasswordQuickAccessState();
    }

    private IEnumerable<PasswordQuickAccessItem> BuildQuickAccessItems(QuickAccessSort sort)
    {
        var records = sort == QuickAccessSort.Frequent
            ? _passwordQuickAccessRecords.Values
                .OrderByDescending(record => record.OpenCount)
                .ThenByDescending(record => record.LastOpenedAt)
            : _passwordQuickAccessRecords.Values
                .OrderByDescending(record => record.LastOpenedAt)
                .ThenByDescending(record => record.OpenCount);

        return records
            .Select(record =>
            {
                var entry = Passwords.FirstOrDefault(item => item.Id == record.PasswordId);
                return entry is null
                    ? null
                    : new PasswordQuickAccessItem(
                        entry,
                        record.OpenCount,
                        record.LastOpenedAt.ToString("g", _localization.Culture),
                        BuildQuickAccessSubtitle(entry));
            })
            .OfType<PasswordQuickAccessItem>()
            .Take(PasswordQuickAccessLimit)
            .ToArray();
    }

    private static string BuildQuickAccessSubtitle(PasswordEntry entry)
    {
        return string.IsNullOrWhiteSpace(entry.Website)
            ? entry.Username
            : string.IsNullOrWhiteSpace(entry.Username)
                ? entry.Website
                : $"{entry.Username} - {entry.Website}";
    }

    private void RaisePasswordQuickAccessState()
    {
        OnPropertyChanged(nameof(RecentPasswordQuickAccessItems));
        OnPropertyChanged(nameof(FrequentPasswordQuickAccessItems));
        OnPropertyChanged(nameof(HasPasswordQuickAccessItems));
    }

    private IEnumerable<PasswordEntry> ApplyPasswordSort(IEnumerable<PasswordEntry> items)
    {
        return SelectedPasswordSort switch
        {
            "title-asc" => items
                .OrderBy(item => NormalizeSortText(item.Title), StringComparer.CurrentCultureIgnoreCase)
                .ThenByDescending(item => item.UpdatedAt)
                .ThenBy(item => item.Id),
            "website-asc" => items
                .OrderBy(item => NormalizeSortText(item.Website), StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(item => NormalizeSortText(item.Title), StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(item => item.Id),
            "username-asc" => items
                .OrderBy(item => NormalizeSortText(item.Username), StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(item => NormalizeSortText(item.Title), StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(item => item.Id),
            "created-desc" => items
                .OrderByDescending(item => item.CreatedAt)
                .ThenBy(item => NormalizeSortText(item.Title), StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(item => item.Id),
            "favorites-first" => items
                .OrderByDescending(item => item.IsFavorite)
                .ThenByDescending(item => item.UpdatedAt)
                .ThenBy(item => NormalizeSortText(item.Title), StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(item => item.Id),
            _ => items
                .OrderByDescending(item => item.UpdatedAt)
                .ThenBy(item => NormalizeSortText(item.Title), StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(item => item.Id)
        };
    }

    private static string NormalizeSortText(string? value)
    {
        var text = value?.Trim();
        return string.IsNullOrEmpty(text) ? "\uffff" : text;
    }

    private Category? GetSelectedPasswordFolderCategory()
    {
        var selectedId = SelectedPasswordFolderFilter?.Id;
        return selectedId is > 0
            ? Categories.FirstOrDefault(item => item.Id == selectedId.Value)
            : null;
    }

    private void RefreshPasswordFolderFilters(long? preferredCategoryId = null)
    {
        var selectedId = preferredCategoryId ?? SelectedPasswordFolderFilter?.Id;
        PasswordFolderFilters.Clear();
        PasswordFolderFilters.Add(new PasswordFolderFilterChoice(null, _localization.Get("AllFolders"), Passwords.Count));
        foreach (var category in Categories.OrderBy(item => item.SortOrder).ThenBy(item => item.Name))
        {
            PasswordFolderFilters.Add(new PasswordFolderFilterChoice(
                category.Id,
                category.Name,
                Passwords.Count(password => password.CategoryId == category.Id)));
        }

        PasswordFolderFilters.Add(new PasswordFolderFilterChoice(
            -1,
            _localization.Get("NoFolder"),
            Passwords.Count(password => password.CategoryId is null)));

        SelectedPasswordFolderFilter =
            PasswordFolderFilters.FirstOrDefault(item => item.Id == selectedId) ??
            PasswordFolderFilters.FirstOrDefault();
        OnPropertyChanged(nameof(FilteredPasswords));
        OnPropertyChanged(nameof(CanManageSelectedPasswordFolder));
    }

    private string ProtectPassword(string password)
    {
        return _cryptoService.IsUnlocked ? _cryptoService.EncryptString(password) : password;
    }

    private IReadOnlyList<string> ProtectPasswords(IReadOnlyList<string> passwords)
    {
        if (passwords.Count == 0)
        {
            return [ProtectPassword("")];
        }

        return passwords.Select(ProtectPassword).ToArray();
    }

    private string UnprotectPassword(string storedPassword)
    {
        if (!_cryptoService.IsUnlocked)
        {
            return storedPassword;
        }

        try
        {
            return _cryptoService.DecryptString(storedPassword);
        }
        catch
        {
            return storedPassword;
        }
    }

    private async Task SavePasswordHistorySnapshotIfChangedAsync(long entryId, string oldPlainPassword, string newPlainPassword)
    {
        if (entryId <= 0 ||
            string.IsNullOrWhiteSpace(oldPlainPassword) ||
            string.Equals(oldPlainPassword, newPlainPassword, StringComparison.Ordinal))
        {
            return;
        }

        var latestHistory = (await _repository.GetPasswordHistoryAsync(entryId)).FirstOrDefault();
        if (latestHistory is not null &&
            string.Equals(UnprotectPassword(latestHistory.Password), oldPlainPassword, StringComparison.Ordinal))
        {
            return;
        }

        await _repository.SavePasswordHistoryAsync(new PasswordHistoryEntry
        {
            EntryId = entryId,
            Password = ProtectPassword(oldPlainPassword),
            LastUsedAt = DateTimeOffset.UtcNow
        });
        await _repository.TrimPasswordHistoryAsync(entryId, PasswordHistoryLimit);
    }

    private async Task<IReadOnlyList<PasswordHistoryDisplayItem>> GetPasswordHistoryDisplayItemsAsync(long entryId)
    {
        var history = await _repository.GetPasswordHistoryAsync(entryId);
        return history
            .Select(item =>
            {
                var password = TryUnprotectHistoryPassword(item.Password);
                return new PasswordHistoryDisplayItem(item, password.DisplayValue, password.CanCopy);
            })
            .ToArray();
    }

    private (string DisplayValue, bool CanCopy) TryUnprotectHistoryPassword(string storedPassword)
    {
        if (string.IsNullOrWhiteSpace(storedPassword))
        {
            return (_localization.Get("PasswordHistoryUnavailable"), false);
        }

        if (!_cryptoService.IsUnlocked)
        {
            return ("********", false);
        }

        try
        {
            return (_cryptoService.DecryptString(storedPassword), true);
        }
        catch
        {
            return (storedPassword, true);
        }
    }

    private async Task DeletePasswordHistoryAsync(PasswordHistoryEntry entry)
    {
        await _repository.DeletePasswordHistoryAsync(entry.Id);
        StatusMessage = _localization.Get("DeletedPasswordHistoryEntry");
    }

    private async Task ClearPasswordHistoryAsync(long entryId)
    {
        await _repository.ClearPasswordHistoryAsync(entryId);
        StatusMessage = _localization.Get("ClearedPasswordHistory");
    }

    private PasswordEntry ClonePasswordForExport(PasswordEntry source)
    {
        var clone = ClonePassword(source);
        clone.Password = UnprotectPassword(source.Password);
        return clone;
    }

    private PasswordEntry ClonePasswordForImport(PasswordEntry source)
    {
        var clone = ClonePassword(source);
        clone.Id = 0;
        clone.Password = ProtectPassword(UnprotectPassword(source.Password));
        clone.IsDeleted = false;
        clone.DeletedAt = null;
        clone.IsArchived = false;
        clone.ArchivedAt = null;
        clone.BitwardenLocalModified = true;
        return clone;
    }

    private static PasswordEntry ClonePassword(PasswordEntry source)
    {
        return new PasswordEntry
        {
            Id = source.Id,
            Title = source.Title,
            Website = source.Website,
            Username = source.Username,
            Password = source.Password,
            Notes = source.Notes,
            IsFavorite = source.IsFavorite,
            SortOrder = source.SortOrder,
            IsGroupCover = source.IsGroupCover,
            AppPackageName = source.AppPackageName,
            AppName = source.AppName,
            Email = source.Email,
            Phone = source.Phone,
            AddressLine = source.AddressLine,
            City = source.City,
            State = source.State,
            ZipCode = source.ZipCode,
            Country = source.Country,
            CreditCardNumber = source.CreditCardNumber,
            CreditCardHolder = source.CreditCardHolder,
            CreditCardExpiry = source.CreditCardExpiry,
            CreditCardCvv = source.CreditCardCvv,
            CategoryId = source.CategoryId,
            BoundNoteId = source.BoundNoteId,
            KeepassDatabaseId = source.KeepassDatabaseId,
            KeepassGroupPath = source.KeepassGroupPath,
            KeepassEntryUuid = source.KeepassEntryUuid,
            KeepassGroupUuid = source.KeepassGroupUuid,
            MdbxDatabaseId = source.MdbxDatabaseId,
            MdbxFolderId = source.MdbxFolderId,
            AuthenticatorKey = source.AuthenticatorKey,
            PasskeyBindings = source.PasskeyBindings,
            SshKeyData = source.SshKeyData,
            LoginType = source.LoginType,
            SsoProvider = source.SsoProvider,
            SsoRefEntryId = source.SsoRefEntryId,
            WifiMetadata = source.WifiMetadata,
            CustomIconType = source.CustomIconType,
            CustomIconValue = source.CustomIconValue,
            CustomIconUpdatedAt = source.CustomIconUpdatedAt,
            IsDeleted = source.IsDeleted,
            DeletedAt = source.DeletedAt,
            IsArchived = source.IsArchived,
            ArchivedAt = source.ArchivedAt,
            ReplicaGroupId = source.ReplicaGroupId,
            BitwardenVaultId = source.BitwardenVaultId,
            BitwardenCipherId = source.BitwardenCipherId,
            BitwardenFolderId = source.BitwardenFolderId,
            BitwardenRevisionDate = source.BitwardenRevisionDate,
            BitwardenCipherType = source.BitwardenCipherType,
            BitwardenLocalModified = source.BitwardenLocalModified,
            CreatedAt = source.CreatedAt,
            UpdatedAt = source.UpdatedAt
        };
    }

    private static SecureItem CloneSecureItemForExport(SecureItem source)
    {
        return CloneSecureItem(source);
    }

    private static SecureItem CloneSecureItemForImport(SecureItem source, IReadOnlyDictionary<long, long> passwordIdMap)
    {
        var clone = CloneSecureItem(source);
        clone.Id = 0;
        if (clone.BoundPasswordId is { } boundPasswordId)
        {
            clone.BoundPasswordId = passwordIdMap.TryGetValue(boundPasswordId, out var importedPasswordId)
                ? importedPasswordId
                : null;
        }

        clone.IsDeleted = false;
        clone.DeletedAt = null;
        clone.BitwardenLocalModified = true;
        clone.SyncStatus = clone.BitwardenVaultId is null ? SyncStatus.None : SyncStatus.Pending;
        return clone;
    }

    private static SecureItem CloneSecureItem(SecureItem source)
    {
        return new SecureItem
        {
            Id = source.Id,
            ItemType = source.ItemType,
            Title = source.Title,
            Notes = source.Notes,
            IsFavorite = source.IsFavorite,
            SortOrder = source.SortOrder,
            CreatedAt = source.CreatedAt,
            UpdatedAt = source.UpdatedAt,
            ItemData = source.ItemData,
            ImagePaths = source.ImagePaths,
            BoundPasswordId = source.BoundPasswordId,
            CategoryId = source.CategoryId,
            KeepassDatabaseId = source.KeepassDatabaseId,
            KeepassGroupPath = source.KeepassGroupPath,
            KeepassEntryUuid = source.KeepassEntryUuid,
            KeepassGroupUuid = source.KeepassGroupUuid,
            MdbxDatabaseId = source.MdbxDatabaseId,
            MdbxFolderId = source.MdbxFolderId,
            IsDeleted = source.IsDeleted,
            DeletedAt = source.DeletedAt,
            ReplicaGroupId = source.ReplicaGroupId,
            BitwardenVaultId = source.BitwardenVaultId,
            BitwardenCipherId = source.BitwardenCipherId,
            BitwardenFolderId = source.BitwardenFolderId,
            BitwardenRevisionDate = source.BitwardenRevisionDate,
            BitwardenLocalModified = source.BitwardenLocalModified,
            SyncStatus = source.SyncStatus
        };
    }

    private void ReplacePasswordGroup(IReadOnlyList<PasswordEntry> previousEntries, IReadOnlyList<PasswordEntry> updatedEntries)
    {
        foreach (var previous in previousEntries)
        {
            Passwords.Remove(previous);
            var current = Passwords.FirstOrDefault(item => item.Id == previous.Id);
            if (current is not null)
            {
                Passwords.Remove(current);
            }
        }

        for (var index = updatedEntries.Count - 1; index >= 0; index--)
        {
            updatedEntries[index].IsSelected = false;
            TrackPasswordSelection(updatedEntries[index]);
            Passwords.Insert(0, updatedEntries[index]);
        }

        RaisePasswordSelectionState();
    }

    private static IReadOnlyList<CustomField> BindCustomFields(long entryId, IReadOnlyList<CustomField> fields)
    {
        return fields
            .Select((field, index) => new CustomField
            {
                EntryId = entryId,
                Title = field.Title,
                Value = field.Value,
                IsProtected = field.IsProtected,
                SortOrder = index
            })
            .ToArray();
    }

    private void SetPasswordCustomFields(long entryId, IReadOnlyList<CustomField> fields)
    {
        var next = _passwordCustomFields.ToDictionary(pair => pair.Key, pair => pair.Value);
        if (fields.Count == 0)
        {
            next.Remove(entryId);
        }
        else
        {
            next[entryId] = fields;
        }

        _passwordCustomFields = next;
    }

    private IReadOnlyList<Attachment> GetPasswordAttachments(long entryId)
    {
        return _passwordAttachments.TryGetValue(entryId, out var attachments)
            ? attachments
            : [];
    }

    private IReadOnlyList<Attachment> GetGroupAttachments(PasswordEntry entry, IReadOnlyList<PasswordEntry> siblings)
    {
        var siblingIds = siblings.Count == 0
            ? [entry.Id]
            : siblings.Select(item => item.Id).ToArray();
        return siblingIds
            .SelectMany(GetPasswordAttachments)
            .OrderByDescending(attachment => attachment.CreatedAt)
            .ThenByDescending(attachment => attachment.Id)
            .ToArray();
    }

    private void SetPasswordAttachments(long entryId, IReadOnlyList<Attachment> attachments)
    {
        var next = _passwordAttachments.ToDictionary(pair => pair.Key, pair => pair.Value);
        if (attachments.Count == 0)
        {
            next.Remove(entryId);
        }
        else
        {
            next[entryId] = attachments;
        }

        _passwordAttachments = next;
    }

    private void RefreshPasswordAttachmentState(PasswordEntry entry)
    {
        entry.HasAttachments = GetPasswordAttachments(entry.Id).Count > 0;
    }

    private async Task<IReadOnlyList<CustomField>> GetGroupCustomFieldsAsync(PasswordEntry entry, IReadOnlyList<PasswordEntry> siblings)
    {
        foreach (var candidate in siblings)
        {
            var fields = await _repository.GetCustomFieldsAsync(candidate.Id);
            if (fields.Count > 0 || candidate.Id == entry.Id)
            {
                return fields;
            }
        }

        return [];
    }

    private async Task LoadTotpItemsAsync()
    {
        TotpItems.Clear();
        var storedTotps = await _repository.GetSecureItemsAsync(VaultItemType.Totp);
        var activePasswordIds = Passwords.Select(item => item.Id).ToHashSet();
        var seenVirtualPasswordIds = new HashSet<long>();

        foreach (var item in storedTotps)
        {
            if (item.BoundPasswordId is { } boundPasswordId && !activePasswordIds.Contains(boundPasswordId))
            {
                continue;
            }

            RefreshTotpDisplay(item);
            TotpItems.Add(item);
            if (item.BoundPasswordId is { } passwordId)
            {
                seenVirtualPasswordIds.Add(passwordId);
            }
        }

        foreach (var password in Passwords.Where(item => item.HasAuthenticator && !seenVirtualPasswordIds.Contains(item.Id)))
        {
            var virtualItem = BuildVirtualTotpItem(password);
            RefreshTotpDisplay(virtualItem);
            TotpItems.Add(virtualItem);
        }
    }

    private async Task LoadTimelineAsync()
    {
        TimelineEntries.Clear();
        foreach (var log in await _repository.GetOperationLogsAsync(150))
        {
            TimelineEntries.Add(new TimelineEntry(
                string.IsNullOrWhiteSpace(log.ItemTitle) ? _localization.Get("Untitled") : log.ItemTitle,
                _localization.Format("TimelineEntryDescriptionFormat", LocalizeOperationType(log.OperationType), log.ItemType, log.DeviceName),
                log.Timestamp.LocalDateTime.ToString("g", _localization.Culture),
                log.OperationType,
                log.ItemType));
        }

        OnPropertyChanged(nameof(TimelineCountText));
    }

    [RelayCommand]
    private async Task CheckCompromisedPasswordsAsync()
    {
        if (IsCheckingCompromisedPasswords)
        {
            return;
        }

        var snapshots = BuildSecurityPasswordSnapshots();
        var plainPasswords = snapshots
            .Select(item => item.PlainPassword)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        IsCheckingCompromisedPasswords = true;
        CompromisedPasswordStatus = _localization.Format("CompromisedPasswordCheckingFormat", plainPasswords.Length);

        try
        {
            var countsByPassword = await _pwnedPasswordService.CheckPasswordsAsync(plainPasswords);
            var next = new Dictionary<long, CompromisedPasswordResult>();
            foreach (var snapshot in snapshots.Where(item => !string.IsNullOrWhiteSpace(item.PlainPassword)))
            {
                if (!countsByPassword.TryGetValue(snapshot.PlainPassword, out var count) || count <= 0)
                {
                    continue;
                }

                next[snapshot.Entry.Id] = new CompromisedPasswordResult(HashPasswordForSecurityCache(snapshot.PlainPassword), count);
            }

            _compromisedPasswordResults = next;
            _hasCompromisedPasswordCheckResults = true;
            CompromisedPasswordStatus = _localization.Format(
                "CompromisedPasswordCheckCompleteFormat",
                plainPasswords.Length,
                next.Count);
            RefreshSecurityAnalysis();
        }
        catch (Exception ex)
        {
            CompromisedPasswordStatus = _localization.Format("CompromisedPasswordCheckUnavailableFormat", ex.Message);
        }
        finally
        {
            IsCheckingCompromisedPasswords = false;
        }
    }

    public void RefreshSecurityAnalysis()
    {
        SecuritySummaryItems.Clear();
        SecurityIssueItems.Clear();

        var analyzed = BuildSecurityPasswordSnapshots();

        var compromisedCount = AddCompromisedPasswordIssues(analyzed);
        var weakCount = AddWeakPasswordIssues(analyzed);
        var duplicatePasswordCount = AddDuplicatePasswordIssues(analyzed);
        var duplicateWebsiteCount = AddDuplicateWebsiteIssues(analyzed);
        var missingTwoFactorCount = AddMissingTwoFactorIssues(analyzed);
        var staleCount = AddStalePasswordIssues(analyzed);

        var totalPenalty =
            compromisedCount * 10 +
            weakCount * 4 +
            duplicatePasswordCount * 6 +
            duplicateWebsiteCount * 2 +
            missingTwoFactorCount * 2 +
            staleCount;
        var score = Math.Clamp(100 - totalPenalty, 0, 100);

        SecuritySummaryItems.Add(new SecuritySummaryItem(
            _localization.SecurityScore,
            _localization.Format("SecurityScoreFormat", score),
            _localization.Format("SecurityAnalyzedPasswordCountFormat", analyzed.Length)));
        SecuritySummaryItems.Add(new SecuritySummaryItem(
            _localization.CompromisedPasswords,
            _hasCompromisedPasswordCheckResults ? compromisedCount.ToString(_localization.Culture) : "-",
            _localization.Get("CompromisedPasswordsSummary")));
        SecuritySummaryItems.Add(new SecuritySummaryItem(
            _localization.WeakPasswords,
            weakCount.ToString(_localization.Culture),
            _localization.Get("WeakPasswordsSummary")));
        SecuritySummaryItems.Add(new SecuritySummaryItem(
            _localization.DuplicatePasswords,
            duplicatePasswordCount.ToString(_localization.Culture),
            _localization.Get("DuplicatePasswordsSummary")));
        SecuritySummaryItems.Add(new SecuritySummaryItem(
            _localization.MissingTwoFactor,
            missingTwoFactorCount.ToString(_localization.Culture),
            _localization.Get("MissingTwoFactorSummary")));

        var orderedIssues = SecurityIssueItems
            .OrderByDescending(item => item.SeverityWeight)
            .ThenBy(item => item.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
        SecurityIssueItems.Clear();
        foreach (var issue in orderedIssues)
        {
            SecurityIssueItems.Add(issue);
        }

        OnPropertyChanged(nameof(SecurityIssueCountText));
    }

    private SecurityPasswordSnapshot[] BuildSecurityPasswordSnapshots()
    {
        return Passwords
            .Where(item => !item.IsDeleted && !item.IsArchived)
            .Select(item => new SecurityPasswordSnapshot(
                item,
                UnprotectPassword(item.Password).Trim(),
                SplitAndNormalizeWebsites(item.Website).ToArray()))
            .ToArray();
    }

    private int AddCompromisedPasswordIssues(IReadOnlyList<SecurityPasswordSnapshot> snapshots)
    {
        if (!_hasCompromisedPasswordCheckResults || _compromisedPasswordResults.Count == 0)
        {
            return 0;
        }

        var count = 0;
        foreach (var snapshot in snapshots.Where(item => !string.IsNullOrWhiteSpace(item.PlainPassword)))
        {
            if (!_compromisedPasswordResults.TryGetValue(snapshot.Entry.Id, out var result) ||
                !string.Equals(result.PasswordHash, HashPasswordForSecurityCache(snapshot.PlainPassword), StringComparison.Ordinal) ||
                result.ExposureCount <= 0)
            {
                continue;
            }

            count++;
            SecurityIssueItems.Add(new SecurityIssueItem(
                snapshot.Entry.Title,
                _localization.Format("CompromisedPasswordIssueFormat", result.ExposureCount),
                _localization.CompromisedPasswords,
                _localization.Get("HighSeverity"),
                snapshot.Entry.Id,
                snapshot.Entry,
                40));
        }

        return count;
    }

    private int AddWeakPasswordIssues(IReadOnlyList<SecurityPasswordSnapshot> snapshots)
    {
        var count = 0;
        foreach (var snapshot in snapshots)
        {
            if (string.IsNullOrWhiteSpace(snapshot.PlainPassword))
            {
                continue;
            }

            var strength = _passwordGenerator.Analyze(snapshot.PlainPassword);
            if (strength.Score > 2)
            {
                continue;
            }

            count++;
            SecurityIssueItems.Add(new SecurityIssueItem(
                snapshot.Entry.Title,
                _localization.Format("WeakPasswordIssueFormat", strength.Label),
                _localization.WeakPasswords,
                _localization.Get("HighSeverity"),
                snapshot.Entry.Id,
                snapshot.Entry,
                30));
        }

        return count;
    }

    private int AddDuplicatePasswordIssues(IReadOnlyList<SecurityPasswordSnapshot> snapshots)
    {
        var count = 0;
        foreach (var group in snapshots
            .Where(item => !string.IsNullOrWhiteSpace(item.PlainPassword))
            .GroupBy(item => item.PlainPassword, StringComparer.Ordinal)
            .Where(group => group.Count() > 1))
        {
            var titles = string.Join(", ", group.Select(item => item.Entry.Title).Distinct().Take(3));
            foreach (var snapshot in group)
            {
                count++;
                SecurityIssueItems.Add(new SecurityIssueItem(
                    snapshot.Entry.Title,
                    _localization.Format("DuplicatePasswordIssueFormat", group.Count(), titles),
                    _localization.DuplicatePasswords,
                    _localization.Get("HighSeverity"),
                    snapshot.Entry.Id,
                    snapshot.Entry,
                    28));
            }
        }

        return count;
    }

    private int AddDuplicateWebsiteIssues(IReadOnlyList<SecurityPasswordSnapshot> snapshots)
    {
        var websites = snapshots
            .SelectMany(snapshot => snapshot.NormalizedWebsites.Select(website => new WebsiteSnapshot(snapshot.Entry, website)))
            .GroupBy(item => item.Website, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Select(item => item.Entry.Id).Distinct().Count() > 1);

        var count = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in websites)
        {
            var entries = group
                .GroupBy(item => item.Entry.Id)
                .Select(item => item.First().Entry)
                .ToArray();
            foreach (var entry in entries)
            {
                if (!seen.Add($"{entry.Id}:{group.Key}"))
                {
                    continue;
                }

                count++;
                SecurityIssueItems.Add(new SecurityIssueItem(
                    entry.Title,
                    _localization.Format("DuplicateWebsiteIssueFormat", group.Key, entries.Length),
                    _localization.DuplicateWebsites,
                    _localization.Get("MediumSeverity"),
                    entry.Id,
                    entry,
                    18));
            }
        }

        return count;
    }

    private int AddMissingTwoFactorIssues(IReadOnlyList<SecurityPasswordSnapshot> snapshots)
    {
        var count = 0;
        foreach (var snapshot in snapshots)
        {
            if (snapshot.Entry.HasAuthenticator ||
                !string.IsNullOrWhiteSpace(snapshot.Entry.PasskeyBindings) ||
                snapshot.Entry.LoginType is not PasswordLoginType.Password ||
                snapshot.NormalizedWebsites.Length == 0)
            {
                continue;
            }

            var domain = snapshot.NormalizedWebsites.First();
            if (!KnownTwoFactorDomains.Any(known => domain.Equals(known, StringComparison.OrdinalIgnoreCase) || domain.EndsWith($".{known}", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            count++;
            SecurityIssueItems.Add(new SecurityIssueItem(
                snapshot.Entry.Title,
                _localization.Format("MissingTwoFactorIssueFormat", domain),
                _localization.MissingTwoFactor,
                _localization.Get("MediumSeverity"),
                snapshot.Entry.Id,
                snapshot.Entry,
                16));
        }

        return count;
    }

    private int AddStalePasswordIssues(IReadOnlyList<SecurityPasswordSnapshot> snapshots)
    {
        var threshold = DateTimeOffset.UtcNow.AddDays(-365);
        var count = 0;
        foreach (var snapshot in snapshots.Where(item => item.Entry.UpdatedAt < threshold))
        {
            count++;
            SecurityIssueItems.Add(new SecurityIssueItem(
                snapshot.Entry.Title,
                _localization.Format("StalePasswordIssueFormat", snapshot.Entry.UpdatedAt.LocalDateTime.ToString("d", _localization.Culture)),
                _localization.StalePasswords,
                _localization.Get("LowSeverity"),
                snapshot.Entry.Id,
                snapshot.Entry,
                8));
        }

        return count;
    }

    private string LocalizeOperationType(string operationType)
    {
        return operationType.ToUpperInvariant() switch
        {
            "CREATE" => _localization.Get("OperationCreate"),
            "UPDATE" => _localization.Get("OperationUpdate"),
            "DELETE" => _localization.Get("OperationDelete"),
            "RESTORE" => _localization.Get("OperationRestore"),
            "PURGE" => _localization.Get("OperationPurge"),
            "FAVORITE" => _localization.Get("OperationFavorite"),
            "MOVE_CATEGORY" => _localization.Get("OperationMoveCategory"),
            "STACK" => _localization.Get("OperationStack"),
            "ATTACHMENT" => _localization.Get("OperationAttachment"),
            "ARCHIVE" => _localization.Get("OperationArchive"),
            "UNARCHIVE" => _localization.Get("OperationUnarchive"),
            "IMPORT" => _localization.Get("OperationImport"),
            _ => operationType
        };
    }

    private void RefreshPasswordTotpDisplay(PasswordEntry entry)
    {
        var data = TotpDataResolver.FromAuthenticatorKey(entry.AuthenticatorKey, entry.Title, entry.Username);
        if (data is null || string.IsNullOrWhiteSpace(data.Secret))
        {
            entry.TotpCode = "------";
            entry.TotpTimeRemaining = "";
            entry.TotpProgress = 0;
            return;
        }

        entry.TotpCode = _totpService.GenerateCode(data.Secret, data.Period, data.Digits, data.OtpType, data.Counter);
        entry.TotpTimeRemaining = $"{_totpService.GetRemainingSeconds(data.Period)}s";
        entry.TotpProgress = _totpService.GetProgress(data.Period);
    }

    private async Task SynchronizeBoundTotpAsync(PasswordEntry entry)
    {
        var existing = await _repository.GetSecureItemsByBoundPasswordIdAsync(entry.Id, includeDeleted: true);
        var active = existing.Where(item => !item.IsDeleted).OrderBy(item => item.Id).ToArray();
        var data = TotpDataResolver.FromAuthenticatorKey(entry.AuthenticatorKey, entry.Title, entry.Username);
        if (data is null || string.IsNullOrWhiteSpace(data.Secret))
        {
            foreach (var item in active)
            {
                await _repository.SoftDeleteSecureItemAsync(item.Id);
            }

            return;
        }

        var primary = active.FirstOrDefault() ?? existing.OrderBy(item => item.Id).FirstOrDefault() ?? new SecureItem
        {
            ItemType = VaultItemType.Totp,
            CreatedAt = DateTimeOffset.UtcNow
        };

        primary.ItemType = VaultItemType.Totp;
        primary.Title = entry.Title;
        primary.Notes = string.IsNullOrWhiteSpace(data.AccountName) ? entry.Username : data.AccountName;
        primary.ItemData = TotpDataResolver.ToItemData(data);
        primary.BoundPasswordId = entry.Id;
        primary.CategoryId = entry.CategoryId;
        primary.KeepassDatabaseId = entry.KeepassDatabaseId;
        primary.KeepassGroupPath = entry.KeepassGroupPath;
        primary.KeepassEntryUuid = entry.KeepassEntryUuid;
        primary.KeepassGroupUuid = entry.KeepassGroupUuid;
        primary.MdbxDatabaseId = entry.MdbxDatabaseId;
        primary.MdbxFolderId = entry.MdbxFolderId;
        primary.BitwardenVaultId = entry.BitwardenVaultId;
        primary.BitwardenFolderId = entry.BitwardenFolderId;
        primary.BitwardenCipherId = entry.BitwardenCipherId;
        primary.BitwardenRevisionDate = entry.BitwardenRevisionDate;
        primary.BitwardenLocalModified = entry.BitwardenLocalModified;
        primary.IsDeleted = false;
        primary.DeletedAt = null;
        primary.SyncStatus = entry.BitwardenVaultId is null ? SyncStatus.None : SyncStatus.Pending;
        await _repository.SaveSecureItemAsync(primary);

        foreach (var duplicate in active.Skip(1))
        {
            await _repository.SoftDeleteSecureItemAsync(duplicate.Id);
        }
    }

    private static SecureItem BuildVirtualTotpItem(PasswordEntry entry)
    {
        var data = TotpDataResolver.FromAuthenticatorKey(entry.AuthenticatorKey, entry.Title, entry.Username);
        return new SecureItem
        {
            Id = -entry.Id,
            ItemType = VaultItemType.Totp,
            Title = entry.Title,
            Notes = string.IsNullOrWhiteSpace(data?.AccountName) ? entry.Username : data.AccountName,
            ItemData = data is null ? "{}" : TotpDataResolver.ToItemData(data),
            BoundPasswordId = entry.Id,
            CategoryId = entry.CategoryId,
            CreatedAt = entry.CreatedAt,
            UpdatedAt = entry.UpdatedAt
        };
    }

    private bool MatchesPasswordFilters(PasswordEntry item)
    {
        if (SelectedPasswordFolderFilter?.Id is { } folderId)
        {
            if (folderId == -1)
            {
                if (item.CategoryId is not null)
                {
                    return false;
                }
            }
            else if (item.CategoryId != folderId)
            {
                return false;
            }
        }

        if (QuickFilterFavorite && !item.IsFavorite)
        {
            return false;
        }

        if (QuickFilter2Fa && !item.HasAuthenticator)
        {
            return false;
        }

        if (QuickFilterNotes && string.IsNullOrWhiteSpace(item.Notes))
        {
            return false;
        }

        if (QuickFilterPasskey && string.IsNullOrWhiteSpace(item.PasskeyBindings))
        {
            return false;
        }

        if (QuickFilterBoundNote && item.BoundNoteId is null)
        {
            return false;
        }

        if (QuickFilterUncategorized && item.CategoryId is not null)
        {
            return false;
        }

        if (QuickFilterLocalOnly && !IsLocalOnlyPassword(item))
        {
            return false;
        }

        if (QuickFilterAttachments && !item.HasAttachments)
        {
            return false;
        }

        return MatchesPasswordSearch(item, SearchText);
    }

    private bool MatchesPasswordSearch(PasswordEntry item, string query)
    {
        var term = query.Trim();
        if (term.Length == 0)
        {
            return true;
        }

        if (ContainsAny(term,
            item.Title,
            item.Username,
            item.Website,
            item.Notes,
            item.AuthenticatorKey,
            item.AppName,
            item.AppPackageName,
            item.Email,
            item.Phone,
            item.AddressLine,
            item.City,
            item.State,
            item.ZipCode,
            item.Country,
            item.CreditCardHolder,
            item.CreditCardExpiry,
            item.SsoProvider,
            item.PasskeyBindings,
            item.WifiMetadata,
            item.SshKeyData,
            item.KeepassGroupPath ?? "",
            item.MdbxFolderId ?? "",
            item.BitwardenFolderId ?? ""))
        {
            return true;
        }

        if (_passwordCustomFields.TryGetValue(item.Id, out var fields) &&
            fields.Any(field => ContainsAny(term, field.Title, field.Value)))
        {
            return true;
        }

        return _passwordAttachments.TryGetValue(item.Id, out var attachments) &&
            attachments.Any(attachment => ContainsAny(
                term,
                attachment.FileName,
                attachment.ContentType,
                attachment.StoragePath,
                attachment.KeepassBinaryRef ?? ""));
    }

    private static bool IsLocalOnlyPassword(PasswordEntry item)
    {
        return item.BitwardenVaultId is null &&
            item.KeepassDatabaseId is null &&
            item.MdbxDatabaseId is null;
    }

    private static bool ContainsAny(string query, params string[] values) =>
        values.Any(value => value.Contains(query, StringComparison.OrdinalIgnoreCase));

    private IEnumerable<PasswordEntry> GetPasswordSiblings(PasswordEntry entry)
    {
        var key = BuildSiblingGroupKey(entry);
        return Passwords
            .Where(item => BuildSiblingGroupKey(item) == key)
            .OrderBy(item => item.Id == 0 ? long.MaxValue : item.Id);
    }

    private IEnumerable<PasswordEntry> GetDeletedPasswordSiblings(PasswordEntry entry)
    {
        var key = BuildSiblingGroupKey(entry);
        return DeletedPasswords
            .Where(item => BuildSiblingGroupKey(item) == key)
            .OrderBy(item => item.Id == 0 ? long.MaxValue : item.Id);
    }

    private IEnumerable<PasswordEntry> GetArchivedPasswordSiblings(PasswordEntry entry)
    {
        var key = BuildSiblingGroupKey(entry);
        return ArchivedPasswords
            .Where(item => BuildSiblingGroupKey(item) == key)
            .OrderBy(item => item.Id == 0 ? long.MaxValue : item.Id);
    }

    private static string BuildSiblingGroupKey(PasswordEntry entry)
    {
        if (!string.IsNullOrWhiteSpace(entry.ReplicaGroupId))
        {
            return $"replica:{entry.ReplicaGroupId.Trim()}";
        }

        var sourceKey = entry.BitwardenCipherId is not null
            ? $"bw:{entry.BitwardenVaultId}:{entry.BitwardenCipherId}"
            : entry.BitwardenVaultId is not null
                ? $"bw-local:{entry.BitwardenVaultId}:{entry.BitwardenFolderId ?? ""}"
                : entry.KeepassDatabaseId is not null
                    ? $"kp:{entry.KeepassDatabaseId}:{entry.KeepassGroupPath ?? ""}"
                    : $"local:{entry.CategoryId?.ToString() ?? "root"}";
        return string.Join("|",
            sourceKey,
            entry.Title.Trim().ToLowerInvariant(),
            NormalizeWebsiteForSiblingGroupKey(entry.Website),
            entry.Username.Trim().ToLowerInvariant());
    }

    private static string NormalizeWebsiteForSiblingGroupKey(string value)
    {
        var normalized = value
            .Trim()
            .ToLowerInvariant();

        if (normalized.StartsWith("http://", StringComparison.Ordinal))
        {
            normalized = normalized["http://".Length..];
        }
        else if (normalized.StartsWith("https://", StringComparison.Ordinal))
        {
            normalized = normalized["https://".Length..];
        }

        if (normalized.StartsWith("www.", StringComparison.Ordinal))
        {
            normalized = normalized["www.".Length..];
        }

        return normalized.TrimEnd('/');
    }

    private static IEnumerable<string> SplitAndNormalizeWebsites(string value)
    {
        return value
            .Split([',', ';', '\n', '\r', '\t', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(NormalizeWebsiteForSecurityAnalysis)
            .Where(item => item.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static string NormalizeWebsiteForSecurityAnalysis(string value)
    {
        var normalized = NormalizeWebsiteForSiblingGroupKey(value);
        var slashIndex = normalized.IndexOf('/', StringComparison.Ordinal);
        if (slashIndex >= 0)
        {
            normalized = normalized[..slashIndex];
        }

        var queryIndex = normalized.IndexOf('?', StringComparison.Ordinal);
        if (queryIndex >= 0)
        {
            normalized = normalized[..queryIndex];
        }

        var fragmentIndex = normalized.IndexOf('#', StringComparison.Ordinal);
        if (fragmentIndex >= 0)
        {
            normalized = normalized[..fragmentIndex];
        }

        return normalized.TrimEnd('.');
    }

    private static string HashPasswordForSecurityCache(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    private sealed record SecurityPasswordSnapshot(PasswordEntry Entry, string PlainPassword, string[] NormalizedWebsites);
    private sealed record WebsiteSnapshot(PasswordEntry Entry, string Website);
    private sealed record CompromisedPasswordResult(string PasswordHash, int ExposureCount);

    private void ApplySettings(DesktopAppSettings settings)
    {
        _isApplyingSettings = true;
        try
        {
            _localization.SetLanguage(settings.Language);
            SettingsLanguage = settings.Language;
            SettingsTheme = settings.Theme;
            StartupSection = settings.StartupSection;
            AutoLockEnabled = settings.AutoLockEnabled;
            AutoLockMinutes = settings.AutoLockMinutes;
            ClearClipboardEnabled = settings.ClearClipboardEnabled;
            ClipboardClearSeconds = settings.ClipboardClearSeconds;
            RequirePasswordBeforeExport = settings.RequirePasswordBeforeExport;
            MinimizeToTray = settings.MinimizeToTray;
            QuickSearchEnabled = settings.QuickSearchEnabled;
            QuickSearchHotkey = settings.QuickSearchHotkey;
            BrowserIntegrationEnabled = settings.BrowserIntegrationEnabled;
            BrowserIntegrationPort = settings.BrowserIntegrationPort;
            CompactPasswordList = settings.CompactPasswordList;
            SelectedPasswordSort = settings.PasswordSortOrder;
            WebDavEnabled = settings.WebDavEnabled;
            WebDavServerUrl = settings.WebDavServerUrl;
            WebDavUsername = settings.WebDavUsername;
            WebDavRemotePath = settings.WebDavRemotePath;
            WebDavSyncOnStartup = settings.WebDavSyncOnStartup;
            WebDavSyncAfterChanges = settings.WebDavSyncAfterChanges;
            SyncConflictStrategy = settings.SyncConflictStrategy;
            OneDriveEnabled = settings.OneDriveEnabled;
            MdbxLocalCacheEnabled = settings.MdbxLocalCacheEnabled;
            ApplyTheme(settings.Theme);
            RefreshLocalizedProperties();
        }
        finally
        {
            _isApplyingSettings = false;
        }
    }

    private void UpdateSettings(Action<DesktopAppSettings> update)
    {
        if (_isApplyingSettings)
        {
            return;
        }

        update(_settingsService.Current);
        QueueSaveSettings();
    }

    private void QueueSaveSettings()
    {
        _ = SaveSettingsAsync();
    }

    private async Task SaveSettingsAsync()
    {
        try
        {
            await _settingsService.SaveAsync();
            StatusMessage = _localization.Get("SettingsSaved");
        }
        catch (Exception ex)
        {
            StatusMessage = _localization.Format("VaultMetadataLoadFailedFormat", ex.Message);
        }
    }

    private void RefreshLocalizedProperties()
    {
        RefreshChoiceLabels();
        RefreshCapabilities();
        OnPropertyChanged(nameof(SelectedSectionTitle));
        OnPropertyChanged(nameof(LoginTitle));
        OnPropertyChanged(nameof(LoginDescription));
        OnPropertyChanged(nameof(LoginButtonText));
        OnPropertyChanged(nameof(GeneratorLengthText));
        OnPropertyChanged(nameof(GeneratedPasswordStrengthText));
        RaisePasswordQuickAccessState();
        RaiseCounts();
        OnPropertyChanged(nameof(SecurityIssueCountText));
        OnPropertyChanged(nameof(NotePreviewMarkdown));
        OnPropertyChanged(nameof(NotePlainPreview));
        if (!_hasCompromisedPasswordCheckResults)
        {
            CompromisedPasswordStatus = _localization.Get("CompromisedPasswordNotChecked");
        }
    }

    private void RefreshChoiceLabels()
    {
        ReplaceOptions(LanguageOptions,
            new("system", _localization.GetLanguageName("system")),
            new("en-US", _localization.GetLanguageName("en-US")),
            new("zh-CN", _localization.GetLanguageName("zh-CN")));

        ReplaceOptions(ThemeOptions,
            new("system", _localization.Get("SystemDefault")),
            new("light", _localization.Get("Light")),
            new("dark", _localization.Get("Dark")));

        ReplaceOptions(StartupSectionOptions,
            new("Passwords", _localization.Passwords),
            new("Notes", _localization.SecureNotes),
            new("Totp", _localization.Totp),
            new("Cards", _localization.Cards),
            new("Generator", _localization.Generator),
            new("Archive", _localization.Archive),
            new("RecycleBin", _localization.RecycleBin),
            new("SecurityAnalysis", _localization.SecurityAnalysis),
            new("Timeline", _localization.Timeline),
            new("Sync", _localization.SyncAndBackup),
            new("Settings", _localization.Settings));

        ReplaceOptions(AutoLockMinuteOptions,
            new(1, _localization.Format("MinuteFormat", 1)),
            new(5, _localization.Format("MinuteFormat", 5)),
            new(15, _localization.Format("MinuteFormat", 15)),
            new(30, _localization.Format("MinuteFormat", 30)),
            new(60, _localization.Format("MinuteFormat", 60)));

        ReplaceOptions(ClipboardSecondOptions,
            new(10, _localization.Format("SecondFormat", 10)),
            new(30, _localization.Format("SecondFormat", 30)),
            new(60, _localization.Format("SecondFormat", 60)),
            new(120, _localization.Format("SecondFormat", 120)));

        ReplaceOptions(ConflictStrategyOptions,
            new("ask", _localization.Get("AskEveryTime")),
            new("local-wins", _localization.Get("LocalWins")),
            new("remote-wins", _localization.Get("RemoteWins")));

        ReplaceOptions(PasswordSortOptions,
            new("updated-desc", _localization.Get("SortUpdated")),
            new("title-asc", _localization.Get("SortTitle")),
            new("website-asc", _localization.Get("SortWebsite")),
            new("username-asc", _localization.Get("SortUsername")),
            new("created-desc", _localization.Get("SortCreated")),
            new("favorites-first", _localization.Get("SortFavorites")));

        OnPropertyChanged(nameof(FilteredPasswords));
    }

    private static void ReplaceOptions(ObservableCollection<SettingsChoice> target, params SettingsChoice[] choices)
    {
        target.Clear();
        foreach (var choice in choices)
        {
            target.Add(choice);
        }
    }

    private void RefreshCapabilities()
    {
        Capabilities.Clear();
        foreach (var capability in _sourceCapabilities)
        {
            Capabilities.Add(new LocalizedPlatformCapability(
                capability.Key,
                _localization.Get($"Capability.{capability.Key}.Title"),
                _localization.Get($"Capability.{capability.Key}.Description"),
                LocalizeFeatureStatus(capability.Status)));
        }
    }

    private string LocalizeFeatureStatus(PlatformFeatureStatus status)
    {
        return status switch
        {
            PlatformFeatureStatus.Available => _localization.Available,
            PlatformFeatureStatus.DesktopEquivalent => _localization.DesktopEquivalent,
            PlatformFeatureStatus.PlatformLimited => _localization.PlatformLimited,
            PlatformFeatureStatus.Planned => _localization.Planned,
            _ => status.ToString()
        };
    }

    private string SectionTitle(string section)
    {
        return section switch
        {
            "Passwords" => _localization.Passwords,
            "Notes" => _localization.SecureNotes,
            "Totp" => _localization.Totp,
            "Cards" => _localization.Cards,
            "Generator" => _localization.Generator,
            "Archive" => _localization.Archive,
            "RecycleBin" => _localization.RecycleBin,
            "SecurityAnalysis" => _localization.SecurityAnalysis,
            "Timeline" => _localization.Timeline,
            "Sync" => _localization.SyncAndBackup,
            "Settings" => _localization.Settings,
            _ => section
        };
    }

    private static void ApplyTheme(string theme)
    {
        if (Application.Current is null)
        {
            return;
        }

        Application.Current.RequestedThemeVariant = theme switch
        {
            "light" => ThemeVariant.Light,
            "dark" => ThemeVariant.Dark,
            _ => ThemeVariant.Default
        };
    }

    private void LoadNoteIntoEditor(SecureItem? item)
    {
        if (item is null)
        {
            return;
        }

        var decoded = NoteContentCodec.DecodeFromItem(item);
        NoteTitle = item.Title;
        NoteContent = decoded.Content;
        NoteTagsText = string.Join(", ", decoded.Tags);
        NoteIsMarkdown = decoded.IsMarkdown;
        NoteIsFavorite = item.IsFavorite;
        NotePreviewMode = decoded.IsMarkdown;
        StatusMessage = _localization.Format("EditingNoteFormat", item.Title);
    }
}
