import csv
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


def test_create_ssh_key_help_has_dynamic_field_options() -> None:
    result = CliRunner().invoke(cli, ["create", "ssh-key", "--help"])

    assert result.exit_code == 0
    assert "--hostname" in result.output
    assert "--private-key" in result.output


def test_create_ssh_key_reads_at_file_values(monkeypatch, tmp_path: Path) -> None:
    class FakeClient:
        def create_typed_secure_note(self, **fields):
            assert fields["note_type"] == "SSH Key"
            assert fields["fields"]["Private Key"] == "private key\n"

    key_path = tmp_path / "id_ed25519"
    key_path.write_text("private key\n")
    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())

    result = CliRunner().invoke(
        cli,
        [
            "create",
            "ssh-key",
            "--name",
            "Production SSH",
            "--hostname=prod.example.com",
            f"--private-key=@{key_path}",
        ],
    )

    assert result.exit_code == 0
    assert result.output == "Production SSH\n"


def test_missing_credentials_is_reported(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LPASS_HOME", str(tmp_path))
    result = CliRunner().invoke(cli, ["status"])

    assert result.exit_code != 0
    assert "run login" in result.output


def test_sync_refreshes_vault(monkeypatch) -> None:
    class FakeClient:
        def sync(self):
            return True

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["sync"])

    assert result.exit_code == 0
    assert result.output == "Synchronized\n"


def test_sync_reports_failure(monkeypatch) -> None:
    class FakeClient:
        def sync(self):
            return False

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["sync"])

    assert result.exit_code != 0
    assert "Could not synchronize vault" in result.output


def test_export_writes_csv_without_passwords_by_default(
    monkeypatch, tmp_path: Path
) -> None:
    class FakeClient:
        def get_secrets(self, include_password=False):
            assert include_password is False
            return [
                {"name": "Example", "username": "user"},
                {"name": "Note", "notes": "line 1\nline 2"},
            ]

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    export_path = tmp_path / "vault.csv"

    result = CliRunner().invoke(cli, ["export", str(export_path)])

    assert result.exit_code == 0
    assert result.output == f"{export_path}\n"
    with export_path.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))
    assert rows == [
        {"name": "Example", "notes": "", "username": "user"},
        {"name": "Note", "notes": "line 1\nline 2", "username": ""},
    ]


def test_export_can_include_passwords_and_filter_by_group(
    monkeypatch, tmp_path: Path
) -> None:
    class FakeClient:
        def get_secrets_by_group(self, group, include_password=False):
            assert group == "Personal"
            assert include_password is True
            return [{"name": "Example", "password": "secret"}]

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    export_path = tmp_path / "personal.csv"

    result = CliRunner().invoke(
        cli, ["export", str(export_path), "--group", "Personal", "--password"]
    )

    assert result.exit_code == 0
    with export_path.open(newline="", encoding="utf-8") as csv_file:
        assert list(csv.DictReader(csv_file)) == [
            {"name": "Example", "password": "secret"}
        ]


def test_import_creates_passwords_from_lastpass_csv(
    monkeypatch, tmp_path: Path
) -> None:
    created = []

    class FakeClient:
        def create_password(self, **fields):
            created.append(fields)

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    import_path = tmp_path / "vault.csv"
    import_path.write_text(
        "url,username,password,extra,name,grouping,fav\n"
        "https://example.com,user,secret,notes,Example,Personal,1\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["import", str(import_path)])

    assert result.exit_code == 0
    assert result.output == "Imported 1 entries\n"
    assert created == [
        {
            "name": "Example",
            "url": "https://example.com",
            "username": "user",
            "password": "secret",
            "notes": "notes",
            "folder_path": "Personal",
            "favorite": True,
        }
    ]


def test_import_accepts_exported_csv_and_secure_notes(
    monkeypatch, tmp_path: Path
) -> None:
    created = []

    class FakeClient:
        def create_password(self, **fields):
            created.append(("password", fields))

        def create_typed_secure_note(self, **fields):
            created.append(("note", fields))

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    import_path = tmp_path / "vault.csv"
    import_path.write_text(
        "url,username,password,extra,name,grouping,fav,type\n"
        "https://example.com,user,secret,notes,Example,Personal,1,Login\n"
        ",,,backup codes,Recovery,Personal,0,Secure Note\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["import", str(import_path)])

    assert result.exit_code == 0
    assert len(created) == 2
    assert created[0][0] == "password"
    assert created[1] == (
        "note",
        {
            "name": "Recovery",
            "note_type": "Generic",
            "folder_path": "Personal",
            "fields": {"Notes": "backup codes"},
            "favorite": False,
        },
    )


def test_import_rejects_invalid_rows_without_creating_entries(
    monkeypatch, tmp_path: Path
) -> None:
    class FakeClient:
        def create_password(self, **fields):
            raise AssertionError("invalid CSV should not create entries")

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    import_path = tmp_path / "vault.csv"
    import_path.write_text("name,type\n,Password\nExample,Card\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["import", str(import_path)])

    assert result.exit_code != 0
    assert "row 2: missing name" in result.output
    assert "row 3: unsupported type" in result.output


def test_logout_removes_saved_credentials(monkeypatch, tmp_path: Path) -> None:
    credential_files = [
        "_response_data",
        "_vault_hash",
        "_vault_key",
        "_session",
        "_username",
    ]
    for filename in credential_files:
        (tmp_path / filename).write_text("credential")
    log_path = tmp_path / "cd-lastpass-cli.log"
    log_path.write_text("log")
    monkeypatch.setenv("LPASS_HOME", str(tmp_path))

    result = CliRunner().invoke(cli, ["logout"])

    assert result.exit_code == 0
    assert result.output == "Logged out\n"
    assert all(not (tmp_path / filename).exists() for filename in credential_files)
    assert log_path.exists()


def test_logout_is_idempotent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LPASS_HOME", str(tmp_path))

    result = CliRunner().invoke(cli, ["logout"])

    assert result.exit_code == 0
    assert result.output == "Logged out\n"


def test_passwd_changes_master_password(monkeypatch) -> None:
    class FakeClient:
        def change_password(self, current_password, new_password):
            assert (current_password, new_password) == ("old secret", "new secret")

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(
        cli, ["passwd"], input="old secret\nnew secret\nnew secret\n"
    )

    assert result.exit_code == 0
    assert result.output.endswith("Password changed\n")


def test_passwd_rejects_mismatched_passwords(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: object())
    result = CliRunner().invoke(cli, ["passwd"], input="old\nnew secret\nother\n")

    assert result.exit_code != 0
    assert "Passwords do not match" in result.output


def test_generate_password_does_not_require_credentials() -> None:
    result = CliRunner().invoke(cli, ["generate"])

    password = result.output.strip()
    assert result.exit_code == 0
    assert len(password) == 20
    assert any(character.islower() for character in password)
    assert any(character.isupper() for character in password)
    assert any(character.isdigit() for character in password)
    assert any(not character.isalnum() for character in password)


def test_generate_password_accepts_length() -> None:
    result = CliRunner().invoke(cli, ["generate", "--length", "32"])

    assert result.exit_code == 0
    assert len(result.output.strip()) == 32


def test_delete_requires_confirmation_and_deletes_entry(monkeypatch) -> None:
    class FakeClient:
        def delete_secret(self, name_or_id):
            assert name_or_id == "Production SSH"
            return True

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["delete", "Production SSH"], input="y\n")

    assert result.exit_code == 0
    assert result.output == (
        "Are you sure you want to delete this entry? [y/N]: y\nProduction SSH\n"
    )


def test_delete_can_skip_confirmation(monkeypatch) -> None:
    class FakeClient:
        def delete_secret(self, name_or_id):
            assert name_or_id == "123"
            return True

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["delete", "123", "--yes"])

    assert result.exit_code == 0
    assert result.output == "123\n"


def test_delete_reports_missing_entry(monkeypatch) -> None:
    class FakeClient:
        def delete_secret(self, name_or_id):
            return False

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["delete", "Missing", "--yes"])

    assert result.exit_code != 0
    assert "Entry not found: Missing" in result.output


def test_move_entry_to_folder(monkeypatch) -> None:
    class FakeClient:
        def move_secret(self, name_or_id, folder_path):
            assert name_or_id == "Production SSH"
            assert folder_path == r"Personal\Infrastructure"
            return True

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(
        cli,
        ["move", "Production SSH", "--folder", r"Personal\Infrastructure"],
    )

    assert result.exit_code == 0
    assert result.output == "Production SSH\n"


def test_move_reports_failure(monkeypatch) -> None:
    class FakeClient:
        def move_secret(self, name_or_id, folder_path):
            return False

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["move", "Missing", "--folder", "Archive"])

    assert result.exit_code != 0
    assert "Could not move entry: Missing" in result.output


def test_share_entry(monkeypatch) -> None:
    class FakeClient:
        def share_secret(self, name_or_id, email):
            assert name_or_id == "Production SSH"
            assert email == "user@example.com"
            return True

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["share", "Production SSH", "user@example.com"])

    assert result.exit_code == 0
    assert result.output == "Production SSH\n"


def test_share_reports_failure(monkeypatch) -> None:
    class FakeClient:
        def share_secret(self, name_or_id, email):
            return False

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["share", "Missing", "user@example.com"])

    assert result.exit_code != 0
    assert "Could not share entry: Missing" in result.output


def test_duplicate_entry(monkeypatch) -> None:
    class FakeClient:
        def duplicate_secret(self, name_or_id, name):
            assert name_or_id == "Production SSH"
            assert name == "Backup SSH"
            return True

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(
        cli, ["duplicate", "Production SSH", "--name", "Backup SSH"]
    )

    assert result.exit_code == 0
    assert result.output == "Backup SSH\n"


def test_duplicate_reports_missing_entry(monkeypatch) -> None:
    class FakeClient:
        def duplicate_secret(self, name_or_id, name):
            return False

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["duplicate", "Missing"])

    assert result.exit_code != 0
    assert "Entry not found: Missing" in result.output


def test_edit_entry_passes_only_supplied_fields(monkeypatch) -> None:
    class FakeClient:
        def edit_secret(self, name_or_id, **updates):
            assert name_or_id == "Production SSH"
            assert updates == {"password": "new secret", "favorite": True}
            return True

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(
        cli,
        ["edit", "Production SSH", "--password", "new secret", "--favorite"],
    )

    assert result.exit_code == 0
    assert result.output == "Production SSH\n"


def test_edit_entry_supports_secure_note_fields(monkeypatch, tmp_path: Path) -> None:
    class FakeClient:
        def edit_secret(self, name_or_id, **updates):
            assert name_or_id == "Recovery"
            assert updates == {"fields": {"Notes": "backup codes\n"}}
            return True

    note_path = tmp_path / "note.txt"
    note_path.write_text("backup codes\n", encoding="utf-8")
    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(
        cli, ["edit", "Recovery", "--field", f"Notes=@{note_path}"]
    )

    assert result.exit_code == 0
    assert result.output == "Recovery\n"


def test_edit_reports_failure(monkeypatch) -> None:
    class FakeClient:
        def edit_secret(self, name_or_id, **updates):
            return False

    monkeypatch.setattr(cli_module, "_get_lastpass", lambda ctx: FakeClient())
    result = CliRunner().invoke(cli, ["edit", "Missing"])

    assert result.exit_code != 0
    assert "Could not edit entry: Missing" in result.output


def test_status_accepts_credentials_from_environment(monkeypatch) -> None:
    class FakeLastpass:
        def __init__(self, username, password, mfa):
            assert (username, password, mfa) == ("user@example.com", "secret", "123456")

    monkeypatch.setattr(cli_module, "Lastpass", FakeLastpass)
    monkeypatch.setattr(
        cli_module.LastpassClient, "_save_credentials", lambda *args: None
    )
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
    monkeypatch.setattr(
        cli_module.LastpassClient, "_save_credentials", lambda *args: None
    )
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
            self.username = username
            self._authenticated_response_data = {}
            self.session = object()
            self._vault = type("Vault", (), {"hash": b"hash", "key": b"key"})()

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(cli_module, "Lastpass", FakeLastpass)
    result = CliRunner().invoke(
        cli,
        ["login", "--username", "user@example.com", "--password", "secret"],
        input="\n",
    )

    assert result.exit_code == 0
    credential_file = tmp_path / ".lastpass-cli" / "_username"
    assert credential_file.read_text() == '"user@example.com"'
    assert credential_file.stat().st_mode & 0o777 == 0o600
