using Avalonia.Controls;
using FluentAvalonia.UI.Controls;

namespace Monica.App.Services;

public interface IConfirmationDialogService
{
    Task<bool> ConfirmAsync(
        string title,
        string message,
        string primaryButtonText,
        string? closeButtonText = null,
        CancellationToken cancellationToken = default);

    Task<bool> ConfirmTypedAsync(
        string title,
        string message,
        string requiredPhrase,
        string instruction,
        string primaryButtonText,
        string? closeButtonText = null,
        CancellationToken cancellationToken = default);
}

public sealed class ConfirmationDialogService(Func<Window> ownerProvider, ILocalizationService localization) : IConfirmationDialogService
{
    public async Task<bool> ConfirmAsync(
        string title,
        string message,
        string primaryButtonText,
        string? closeButtonText = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var dialog = new FAContentDialog
        {
            Title = title,
            Content = new TextBlock
            {
                Text = message,
                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                MaxWidth = 420
            },
            PrimaryButtonText = primaryButtonText,
            CloseButtonText = closeButtonText ?? localization.Cancel,
            DefaultButton = FAContentDialogButton.Close
        };

        var result = await dialog.ShowAsync(ownerProvider());
        return result == FAContentDialogResult.Primary;
    }

    public async Task<bool> ConfirmTypedAsync(
        string title,
        string message,
        string requiredPhrase,
        string instruction,
        string primaryButtonText,
        string? closeButtonText = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var input = new TextBox
        {
            PlaceholderText = requiredPhrase,
            Width = 420
        };

        var dialog = new FAContentDialog
        {
            Title = title,
            Content = new StackPanel
            {
                Spacing = 12,
                Children =
                {
                    new TextBlock
                    {
                        Text = message,
                        TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                        MaxWidth = 420
                    },
                    new TextBlock
                    {
                        Text = instruction,
                        TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                        MaxWidth = 420
                    },
                    input
                }
            },
            PrimaryButtonText = primaryButtonText,
            CloseButtonText = closeButtonText ?? localization.Cancel,
            DefaultButton = FAContentDialogButton.Close
        };

        var result = await dialog.ShowAsync(ownerProvider());
        return result == FAContentDialogResult.Primary &&
            string.Equals(input.Text?.Trim(), requiredPhrase, StringComparison.Ordinal);
    }
}
