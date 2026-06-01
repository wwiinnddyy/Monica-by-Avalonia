using Avalonia.Controls;
using FluentAvalonia.UI.Controls;
using Monica.App.ViewModels;
using Monica.Core.Models;

namespace Monica.App.Services;

public interface ICategoryPickerDialogService
{
    Task<PasswordCategoryChoice?> ShowAsync(
        IReadOnlyList<Category> categories,
        long? selectedCategoryId = null,
        CancellationToken cancellationToken = default);
}

public sealed class CategoryPickerDialogService(
    Func<Window> ownerProvider,
    ILocalizationService localization) : ICategoryPickerDialogService
{
    public async Task<PasswordCategoryChoice?> ShowAsync(
        IReadOnlyList<Category> categories,
        long? selectedCategoryId = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var picker = new CategoryPickerViewModel(localization, categories, selectedCategoryId);
        var dialog = new FAContentDialog
        {
            Title = localization.Get("MoveToFolder"),
            Content = new CategoryPickerDialog { DataContext = picker },
            PrimaryButtonText = localization.Get("Move"),
            CloseButtonText = localization.Cancel,
            DefaultButton = FAContentDialogButton.Primary
        };

        var result = await dialog.ShowAsync(ownerProvider());
        return result == FAContentDialogResult.Primary ? picker.SelectedCategory : null;
    }
}
