namespace Monica.Tests;

public sealed class AppSmokeOptionsTests
{
    private const string DefaultEnvName = "MONICA_SMOKE_UI_UNLOCK_PASSWORD";
    private const string CustomEnvName = "MONICA_SMOKE_UI_UNLOCK_PASSWORD_TEST";
    private const string MissingEnvName = "MONICA_SMOKE_UI_UNLOCK_PASSWORD_MISSING_TEST";

    [Fact]
    public void Smoke_unlock_env_reads_custom_environment_variable()
    {
        WithEnvironment(CustomEnvName, "custom password", () =>
        {
            var password = Monica.App.App.GetSmokeUiUnlockPassword(["--smoke-ui-unlock-env", CustomEnvName]);

            Assert.Equal("custom password", password);
        });
    }

    [Fact]
    public void Smoke_unlock_env_without_name_reads_default_environment_variable()
    {
        WithEnvironment(DefaultEnvName, "default password", () =>
        {
            var password = Monica.App.App.GetSmokeUiUnlockPassword(["--smoke-ui-unlock-env"]);

            Assert.Equal("default password", password);
        });
    }

    [Fact]
    public void Smoke_unlock_env_without_name_reads_default_when_followed_by_other_options()
    {
        WithEnvironment(DefaultEnvName, "default password", () =>
        {
            var password = Monica.App.App.GetSmokeUiUnlockPassword([
                "--smoke-ui-unlock-env",
                "--smoke-ui-width",
                "800"
            ]);

            Assert.Equal("default password", password);
        });
    }

    [Fact]
    public void Smoke_unlock_env_takes_precedence_over_legacy_argument()
    {
        WithEnvironment(CustomEnvName, "env password", () =>
        {
            var password = Monica.App.App.GetSmokeUiUnlockPassword([
                "--smoke-ui-unlock",
                "legacy password",
                "--smoke-ui-unlock-env",
                CustomEnvName
            ]);

            Assert.Equal("env password", password);
        });
    }

    [Fact]
    public void Smoke_unlock_legacy_argument_remains_supported()
    {
        var password = Monica.App.App.GetSmokeUiUnlockPassword(["--smoke-ui-unlock", "legacy password"]);

        Assert.Equal("legacy password", password);
    }

    [Fact]
    public void Smoke_unlock_legacy_argument_allows_option_like_password()
    {
        var password = Monica.App.App.GetSmokeUiUnlockPassword(["--smoke-ui-unlock", "--legacy-looking-password"]);

        Assert.Equal("--legacy-looking-password", password);
    }

    [Fact]
    public void Smoke_unlock_env_missing_value_does_not_fall_back_to_legacy_argument()
    {
        WithEnvironment(MissingEnvName, null, () =>
        {
            var password = Monica.App.App.GetSmokeUiUnlockPassword([
                "--smoke-ui-unlock-env",
                MissingEnvName,
                "--smoke-ui-unlock",
                "legacy password"
            ]);

            Assert.Null(password);
        });
    }

    [Fact]
    public void Smoke_viewport_size_reads_width_and_height()
    {
        var viewport = Monica.App.App.GetSmokeUiViewportSize([
            "--smoke-ui-width",
            "800",
            "--smoke-ui-height",
            "500"
        ]);

        Assert.NotNull(viewport);
        Assert.Equal(800, viewport.Value.Width);
        Assert.Equal(500, viewport.Value.Height);
    }

    [Fact]
    public void Smoke_viewport_size_requires_both_dimensions()
    {
        var viewport = Monica.App.App.GetSmokeUiViewportSize([
            "--smoke-ui-width",
            "1440"
        ]);

        Assert.Null(viewport);
    }

    [Fact]
    public void Smoke_viewport_size_ignores_invalid_dimensions()
    {
        var viewport = Monica.App.App.GetSmokeUiViewportSize([
            "--smoke-ui-width",
            "wide",
            "--smoke-ui-height",
            "900"
        ]);

        Assert.Null(viewport);
    }

    private static void WithEnvironment(string name, string? value, Action test)
    {
        var previous = Environment.GetEnvironmentVariable(name);
        try
        {
            Environment.SetEnvironmentVariable(name, value);
            test();
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, previous);
        }
    }
}
