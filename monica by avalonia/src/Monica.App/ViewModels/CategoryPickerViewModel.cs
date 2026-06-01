using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Monica.App.Services;
using Monica.Core.Models;

namespace Monica.App.ViewModels;

public sealed partial class CategoryPickerViewModel : ObservableObject
{
    public CategoryPickerViewModel(ILocalizationService localization, IEnumerable<Category> categories, long? selectedCategoryId = null)
    {
        L = localization;
        CategoryOptions.Add(new PasswordCategoryChoice(null, localization.Get("NoFolder")));
        foreach (var category in categories.OrderBy(item => item.SortOrder).ThenBy(item => item.Name))
        {
            CategoryOptions.Add(new PasswordCategoryChoice(category.Id, category.Name));
        }

        SelectedCategory = CategoryOptions.FirstOrDefault(item => item.Id == selectedCategoryId) ?? CategoryOptions[0];
    }

    public ILocalizationService L { get; }
    public ObservableCollection<PasswordCategoryChoice> CategoryOptions { get; } = [];

    [ObservableProperty]
    private PasswordCategoryChoice? _selectedCategory;
}
