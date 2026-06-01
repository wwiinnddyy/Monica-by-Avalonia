using System.Security.Cryptography;
using System.Text;

namespace Monica.Core.Services;

public interface IPasswordGeneratorService
{
    string GeneratePassword(int length = 20, bool includeSymbols = true);
    string GeneratePassword(
        int length,
        bool includeUppercase,
        bool includeLowercase,
        bool includeNumbers,
        bool includeSymbols);
    PasswordStrengthResult Analyze(string password);
}

public sealed record PasswordStrengthResult(int Score, string Label, IReadOnlyList<string> Warnings);

public sealed class PasswordGeneratorService : IPasswordGeneratorService
{
    private const string UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string LowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
    private const string Letters = LowercaseLetters + UppercaseLetters;
    private const string Digits = "0123456789";
    private const string Symbols = "!@#$%^&*()-_=+[]{};:,.?";

    public string GeneratePassword(int length = 20, bool includeSymbols = true)
    {
        return GeneratePassword(length, includeUppercase: true, includeLowercase: true, includeNumbers: true, includeSymbols);
    }

    public string GeneratePassword(
        int length,
        bool includeUppercase,
        bool includeLowercase,
        bool includeNumbers,
        bool includeSymbols)
    {
        length = Math.Clamp(length, 8, 128);
        var groups = new List<string>(4);
        if (includeUppercase)
        {
            groups.Add(UppercaseLetters);
        }

        if (includeLowercase)
        {
            groups.Add(LowercaseLetters);
        }

        if (includeNumbers)
        {
            groups.Add(Digits);
        }

        if (includeSymbols)
        {
            groups.Add(Symbols);
        }

        if (groups.Count == 0)
        {
            groups.Add(LowercaseLetters);
        }

        var required = groups
            .Select(group => group[RandomNumberGenerator.GetInt32(group.Length)])
            .ToList();
        var alphabet = string.Concat(groups);
        while (required.Count < length)
        {
            required.Add(alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]);
        }

        for (var index = required.Count - 1; index > 0; index--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(index + 1);
            (required[index], required[swapIndex]) = (required[swapIndex], required[index]);
        }

        return new string(required.Take(length).ToArray());
    }

    public PasswordStrengthResult Analyze(string password)
    {
        var warnings = new List<string>();
        var score = 0;

        if (password.Length >= 12) score++;
        else warnings.Add("Password is shorter than 12 characters.");

        if (password.Any(char.IsLower) && password.Any(char.IsUpper)) score++;
        else warnings.Add("Use both upper and lower case letters.");

        if (password.Any(char.IsDigit)) score++;
        else warnings.Add("Add numbers.");

        if (password.Any(c => !char.IsLetterOrDigit(c))) score++;
        else warnings.Add("Add symbols.");

        if (password.Length >= 20) score++;

        var label = score switch
        {
            >= 5 => "Excellent",
            4 => "Strong",
            3 => "Fair",
            2 => "Weak",
            _ => "Very weak"
        };

        return new PasswordStrengthResult(score, label, warnings);
    }
}
