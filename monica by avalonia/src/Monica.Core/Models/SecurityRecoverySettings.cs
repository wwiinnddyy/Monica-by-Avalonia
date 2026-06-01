namespace Monica.Core.Models;

public sealed class SecurityRecoverySettings
{
    public bool IsEnabled { get; set; }
    public int Question1Id { get; set; } = 11;
    public string Question1Text { get; set; } = "Which Ultraman do you like the most?";
    public string Question1AnswerHash { get; set; } = "";
    public string Question1AnswerSalt { get; set; } = "";
    public int Question2Id { get; set; } = 1;
    public string Question2Text { get; set; } = "What was the name of your first pet?";
    public string Question2AnswerHash { get; set; } = "";
    public string Question2AnswerSalt { get; set; } = "";

    public bool HasCompleteSetup =>
        IsEnabled
        && !string.IsNullOrWhiteSpace(Question1Text)
        && !string.IsNullOrWhiteSpace(Question1AnswerHash)
        && !string.IsNullOrWhiteSpace(Question1AnswerSalt)
        && !string.IsNullOrWhiteSpace(Question2Text)
        && !string.IsNullOrWhiteSpace(Question2AnswerHash)
        && !string.IsNullOrWhiteSpace(Question2AnswerSalt);
}

public sealed record SecurityQuestionDefinition(int Id, string Text);

public sealed record SecurityQuestionDraft(int Id, string Text, string Answer);
