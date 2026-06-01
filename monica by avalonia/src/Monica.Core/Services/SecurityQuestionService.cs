using System.Security.Cryptography;
using System.Text;
using Monica.Core.Models;

namespace Monica.Core.Services;

public sealed class SecurityQuestionService
{
    public const int CustomQuestionId = 10_000;
    private const int Pbkdf2Iterations = 150_000;
    private const int SaltLength = 16;
    private const int HashLength = 32;

    public IReadOnlyList<SecurityQuestionDefinition> PredefinedQuestions { get; } =
    [
        new(11, "Which Ultraman do you like the most?"),
        new(1, "What was the name of your first pet?"),
        new(2, "What is your mother's maiden name?"),
        new(3, "In what city were you born?"),
        new(4, "What was the name of your elementary school?"),
        new(5, "What is your favorite movie?"),
        new(6, "What was your first car model?"),
        new(7, "What is the name of your best friend from childhood?"),
        new(8, "What was your favorite food as a child?"),
        new(9, "What is the name of the street you grew up on?"),
        new(10, "What was your high school mascot?"),
        new(CustomQuestionId, "Custom question")
    ];

    public SecurityQuestionDefinition GetQuestion(int id) =>
        PredefinedQuestions.FirstOrDefault(item => item.Id == id)
        ?? PredefinedQuestions.First(item => item.Id == CustomQuestionId);

    public SecurityRecoverySettings CreateSetup(SecurityQuestionDraft question1, SecurityQuestionDraft question2)
    {
        var normalizedQuestion1 = NormalizeQuestion(question1);
        var normalizedQuestion2 = NormalizeQuestion(question2);
        if (string.Equals(normalizedQuestion1.Text, normalizedQuestion2.Text, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Use two different security questions.");
        }

        var hash1 = HashAnswer(normalizedQuestion1.Answer);
        var hash2 = HashAnswer(normalizedQuestion2.Answer);
        return new SecurityRecoverySettings
        {
            IsEnabled = true,
            Question1Id = normalizedQuestion1.Id,
            Question1Text = normalizedQuestion1.Text,
            Question1AnswerHash = hash1.Hash,
            Question1AnswerSalt = hash1.Salt,
            Question2Id = normalizedQuestion2.Id,
            Question2Text = normalizedQuestion2.Text,
            Question2AnswerHash = hash2.Hash,
            Question2AnswerSalt = hash2.Salt
        };
    }

    public bool VerifyAnswer(string answer, string hash, string salt)
    {
        if (string.IsNullOrWhiteSpace(answer) || string.IsNullOrWhiteSpace(hash) || string.IsNullOrWhiteSpace(salt))
        {
            return false;
        }

        var expected = Convert.FromBase64String(hash);
        var actual = DeriveAnswerHash(answer, Convert.FromBase64String(salt));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private SecurityQuestionDraft NormalizeQuestion(SecurityQuestionDraft draft)
    {
        var text = draft.Id == CustomQuestionId
            ? draft.Text.Trim()
            : GetQuestion(draft.Id).Text;
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new ArgumentException("Security question text is required.");
        }

        if (string.IsNullOrWhiteSpace(draft.Answer))
        {
            throw new ArgumentException("Security question answer is required.");
        }

        return draft with { Text = text };
    }

    private static (string Hash, string Salt) HashAnswer(string answer)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = DeriveAnswerHash(answer, salt);
        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    private static byte[] DeriveAnswerHash(string answer, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(NormalizeAnswer(answer)),
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            HashLength);

    private static string NormalizeAnswer(string answer) =>
        answer.Trim().Normalize(NormalizationForm.FormKC).ToUpperInvariant();
}
