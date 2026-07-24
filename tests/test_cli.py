from importlib import import_module
from pathlib import Path

from click.testing import CliRunner

from cd_lastpass_cli.cli import cli, configure_logging

cli_module = import_module("cd_lastpass_cli.cli")


def test_configure_logging_uses_private_lastpass_cli_directory(tmp_path: Path) -> None:
    log_path = configure_logging({"LPASS_HOME": str(tmp_path)})

    assert log_path == tmp_path / "cd-lastpass-cli.log"
    assert tmp_path.stat().st_mode & 0o777 == 0o700


def test_help_exposes_auto_envvar_prefix() -> None:
    result = CliRunner().invoke(cli, ["login", "--help"])

    assert result.exit_code == 0
    assert "LPASS_USERNAME" in result.output


def test_missing_credentials_is_reported() -> None:
    result = CliRunner().invoke(cli, ["status"])

    assert result.exit_code != 0
    assert "run login" in result.output


def test_status_accepts_credentials_from_environment(monkeypatch) -> None:
    class FakeLastpass:
        def __init__(self, username, password, mfa):
            assert (username, password, mfa) == ("user@example.com", "secret", "123456")

    monkeypatch.setattr(cli_module, "Lastpass", FakeLastpass)
    result = CliRunner().invoke(
        cli_module.cli,
        ["login"],
        env={
            "LPASS_USERNAME": "user@example.com",
            "LPASS_PASSWORD": "secret",
            "LPASS_MFA": "123456",
        },
    )

    assert result.exit_code == 0
    assert result.output == "Logged in\n"


def test_login_prompts_for_empty_password_and_mfa(monkeypatch) -> None:
    class FakeLastpass:
        def __init__(self, username, password, mfa):
            assert (username, password, mfa) == ("user@example.com", "secret", "123456")

    monkeypatch.setattr(cli_module, "Lastpass", FakeLastpass)
    result = CliRunner().invoke(
        cli,
        ["login", "--username", "user@example.com", "--password", "", "--mfa", ""],
        input="secret\n123456\n",
    )

    assert result.exit_code == 0
    assert "Password:" in result.output
    assert "MFA:" in result.output


def test_login_saves_credentials(monkeypatch, tmp_path: Path) -> None:
    class FakeLastpass:
        def __init__(self, username, password, mfa):
            pass

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(cli_module, "Lastpass", FakeLastpass)
    result = CliRunner().invoke(
        cli,
        ["login", "--username", "user@example.com", "--password", "secret"],
        input="\n",
    )

    assert result.exit_code == 0
    assert load_credentials() == {"username": "user@example.com", "password": "secret"}
    assert credential_file().stat().st_mode & 0o777 == 0o600
