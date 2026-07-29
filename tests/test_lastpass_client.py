from pathlib import Path
from typing import ClassVar, cast
from unittest.mock import Mock

import lastpasslib.secrets
import pytest

from cd_lastpass_cli.lastpass_client import Lastpass as LastpassType
from cd_lastpass_cli.lastpass_client import LastpassClient, NoSavedCredentials


def test_delete_secret_resolves_by_name_before_id() -> None:
    class Secret:
        def delete(self):
            return True

    class Lastpass:
        def get_secret_by_name(self, name):
            assert name == "Production SSH"
            return Secret()

        def get_secret_by_id(self, secret_id):
            raise AssertionError("ID lookup should not be needed")

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.delete_secret("Production SSH") is True


def test_sync_refreshes_lastpass_and_saves_credentials() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.refresh.return_value = True
    client._save_credentials = Mock()

    assert client.sync() is True

    client.lastpass.refresh.assert_called_once_with()
    client._save_credentials.assert_called_once_with(client.lastpass)


def test_sync_does_not_save_credentials_when_refresh_fails() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.refresh.return_value = False
    client._save_credentials = Mock()

    assert client.sync() is False

    client.lastpass.refresh.assert_called_once_with()
    client._save_credentials.assert_not_called()


def test_delete_secret_falls_back_to_id() -> None:
    class Secret:
        def delete(self):
            return True

    class Lastpass:
        def get_secret_by_name(self, name):
            return None

        def get_secret_by_id(self, secret_id):
            assert secret_id == "123"
            return Secret()

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.delete_secret("123") is True


def test_delete_secret_returns_false_for_missing_entry() -> None:
    class Lastpass:
        def get_secret_by_name(self, name):
            return None

        def get_secret_by_id(self, secret_id):
            return None

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.delete_secret("Missing") is False


def test_move_secret_resolves_by_name_and_moves_to_folder() -> None:
    class Secret:
        def move_to_folder(self, folder_path):
            assert folder_path == r"Personal\Infrastructure"
            return True

    class Lastpass:
        def get_secret_by_name(self, name):
            assert name == "Production SSH"
            return Secret()

        def get_secret_by_id(self, secret_id):
            raise AssertionError("ID lookup should not be needed")

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.move_secret("Production SSH", r"Personal\Infrastructure") is True


def test_move_secret_falls_back_to_id() -> None:
    class Secret:
        def move_to_folder(self, folder_path):
            assert folder_path == "Archive"
            return True

    class Lastpass:
        def get_secret_by_name(self, name):
            return None

        def get_secret_by_id(self, secret_id):
            assert secret_id == "123"
            return Secret()

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.move_secret("123", "Archive") is True


def test_move_secret_returns_false_for_missing_entry() -> None:
    class Lastpass:
        def get_secret_by_name(self, name):
            return None

        def get_secret_by_id(self, secret_id):
            return None

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.move_secret("Missing", "Archive") is False


def test_share_secret_resolves_by_name_and_shares_with_email() -> None:
    class Secret:
        id = "123"

    class Lastpass:
        def get_secret_by_name(self, name):
            assert name == "Production SSH"
            return Secret()

        def get_secret_by_id(self, secret_id):
            raise AssertionError("ID lookup should not be needed")

        def share_secret(self, secret, email):
            assert secret.id == "123"
            assert email == "user@example.com"
            return True

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.share_secret("Production SSH", "user@example.com") is True


def test_share_secret_returns_false_for_missing_entry() -> None:
    class Lastpass:
        def get_secret_by_name(self, name):
            return None

        def get_secret_by_id(self, secret_id):
            return None

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())

    assert client.share_secret("Missing", "user@example.com") is False


def test_duplicate_password_preserves_password_fields() -> None:
    class Secret(lastpasslib.secrets.Password):
        name = "Production"
        full_path = r"Personal\Infrastructure"
        url = "https://example.com"
        username = "user"
        password = "secret"
        mfa_seed = "seed"
        notes = "notes"
        is_password_protected = True
        auto_login = True
        never_autofill = False
        is_favorite = True

        def __init__(self):
            pass

    class Lastpass:
        def get_secret_by_name(self, name):
            return Secret()

        def get_secret_by_id(self, secret_id):
            raise AssertionError("ID lookup should not be needed")

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())
    create_password = Mock(return_value=True)
    client.create_password = create_password

    assert client.duplicate_secret("Production", "Production Copy") is True
    create_password.assert_called_once_with(
        name="Production Copy",
        url="https://example.com",
        folder_path=r"Personal\Infrastructure",
        username="user",
        password="secret",
        totp="seed",
        notes="notes",
        pwprotect=True,
        auto_login=True,
        autofill=True,
        favorite=True,
    )


def test_duplicate_secure_note_preserves_note_fields() -> None:
    class Secret:
        name = "Recovery"
        full_path = "Personal"
        is_favorite = False
        notes = "Notes"
        attribute_mapping: ClassVar = {"Username": "username", "Notes": "notes"}
        username = "user"
        _data: ClassVar = {"note_type": "Email Account"}

    class Lastpass:
        def get_secret_by_name(self, name):
            return Secret()

        def get_secret_by_id(self, secret_id):
            return None

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())
    create_typed_secure_note = Mock(return_value=True)
    client.create_typed_secure_note = create_typed_secure_note

    assert client.duplicate_secret("Recovery") is True
    create_typed_secure_note.assert_called_once_with(
        name="Copy of Recovery",
        note_type="Email Account",
        folder_path="Personal",
        fields={"Username": "user", "Notes": "Notes"},
        favorite=False,
    )


def test_edit_password_creates_updated_entry_then_deletes_original() -> None:
    class Secret(lastpasslib.secrets.Password):
        name = "Production"
        full_path = "Personal"
        url = "https://example.com"
        username = "user"
        password = "old secret"
        mfa_seed = "seed"
        notes = "notes"
        is_password_protected = False
        auto_login = False
        never_autofill = True
        is_favorite = False

        def delete(self):
            return True

        def __init__(self):
            pass

    class Lastpass:
        def get_secret_by_name(self, name):
            return Secret()

        def get_secret_by_id(self, secret_id):
            raise AssertionError("ID lookup should not be needed")

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())
    client.create_password = Mock(return_value=True)

    assert client.edit_secret("Production", password="new secret") is True
    client.create_password.assert_called_once_with(
        name="Production",
        folder_path="Personal",
        favorite=False,
        url="https://example.com",
        username="user",
        password="new secret",
        totp="seed",
        notes="notes",
    )


def test_edit_secure_note_preserves_type_and_updates_fields() -> None:
    class Secret:
        name = "Recovery"
        full_path = "Personal"
        is_favorite = False
        notes = "old notes"
        attribute_mapping: ClassVar = {"Username": "username", "Notes": "notes"}
        username = "user"
        _data: ClassVar = {"note_type": "Email Account"}

        def delete(self):
            return True

    class Lastpass:
        def get_secret_by_name(self, name):
            return Secret()

        def get_secret_by_id(self, secret_id):
            return None

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = cast(LastpassType, Lastpass())
    client.create_typed_secure_note = Mock(return_value=True)

    assert client.edit_secret("Recovery", fields={"Username": "new user"}) is True
    client.create_typed_secure_note.assert_called_once_with(
        name="Recovery",
        note_type="Email Account",
        folder_path="Personal",
        fields={"Username": "new user", "Notes": "old notes"},
        favorite=False,
    )


def test_config_home_uses_lpass_home_and_secure_permissions(tmp_path: Path) -> None:
    client = LastpassClient.__new__(LastpassClient)

    config_home = client._get_config_home({"LPASS_HOME": str(tmp_path / "config")})

    assert config_home == tmp_path / "config"
    assert config_home.stat().st_mode & 0o777 == 0o700


def test_save_and_load_credentials_round_trip(tmp_path: Path) -> None:
    client = LastpassClient.__new__(LastpassClient)
    client._config_home = tmp_path
    lastpass = Mock()
    lastpass._authenticated_response_data = {"iterations": 100}
    lastpass._vault.hash = b"hash"
    lastpass._vault.key = b"key"
    lastpass.session = Mock()
    lastpass.username = "user@example.com"

    client._save_credentials(lastpass)
    credentials = client._load_credentials()

    assert credentials.username == lastpass.username
    assert credentials.auth_response_data == {"iterations": 100}
    assert credentials.vault_hash == b"hash"
    assert credentials.vault_key == b"key"
    assert all(
        (tmp_path / name).stat().st_mode & 0o777 == 0o600
        for name in client._CREDENTIAL_FILES
    )


def test_load_credentials_raises_for_invalid_saved_data(tmp_path: Path) -> None:
    client = LastpassClient.__new__(LastpassClient)
    client._config_home = tmp_path
    (tmp_path / "_username").write_text("not-json")

    with pytest.raises(NoSavedCredentials):
        client._load_credentials()


def test_logout_ignores_missing_credential_files(tmp_path: Path) -> None:
    LastpassClient.logout({"LPASS_HOME": str(tmp_path)})


def test_get_secrets_processes_password_visibility_and_filter() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.get_secrets.return_value = []

    assert client.get_secrets(include_password=True, filter_="Personal") == []
    client.lastpass.get_secrets.assert_called_once_with(filter_="Personal")


def test_get_secrets_by_group_delegates_to_lastpass() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.get_secrets_by_group.return_value = []

    assert client.get_secrets_by_group("Personal", filter_="SSH") == []
    client.lastpass.get_secrets_by_group.assert_called_once_with(
        group_name="Personal", filter_="SSH"
    )


def test_create_methods_delegate_to_authenticated_client() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.create_password.return_value = True
    client.lastpass.create_typed_secure_note.return_value = True

    assert client.create_password(name="Example") is True
    assert client.create_typed_secure_note(name="Note") is True
    client.lastpass.create_password.assert_called_once_with(name="Example")
    client.lastpass.create_typed_secure_note.assert_called_once_with(name="Note")


def test_get_password_change_info_parses_fields_and_recovery_keys() -> None:
    client = LastpassClient.__new__(LastpassClient)
    lastpass = Mock()
    response = Mock(
        ok=True,
        content=(
            b'<response rc="OK"><data token="token" sukey0="key" suuid0="uid" '
            b'xml="reencrypt&#10;private-key&#10;required&#9;0&#10;optional&#9;1&#10;endmarker" '
            b"/></response>"
        ),
    )
    lastpass.session.post.return_value = response
    lastpass.api_endpoint = "https://example.test/api"
    lastpass.username = "user@example.com"

    info = client._get_password_change_info(lastpass, "hash")

    assert info.token == "token"
    assert info.reencrypt_id == "reencrypt"
    assert info.private_key == "private-key"
    assert info.fields == [("required", False), ("optional", True)]
    assert info.recovery_keys == [("key", "uid")]


@pytest.mark.parametrize(
    "xml, message",
    [
        ('<response rc="ERROR" />', "Unable to start password change."),
        ('<response rc="OK" />', "Invalid password change response."),
        (
            '<response rc="OK"><data xml="only-one-line" /></response>',
            "Invalid password change response.",
        ),
    ],
)
def test_get_password_change_info_rejects_invalid_responses(
    xml: str, message: str
) -> None:
    client = LastpassClient.__new__(LastpassClient)
    lastpass = Mock()
    lastpass.session.post.return_value = Mock(ok=True, content=xml.encode())
    lastpass.api_endpoint = "https://example.test/api"
    lastpass.username = "user@example.com"

    with pytest.raises(ValueError, match=message):
        client._get_password_change_info(lastpass, "hash")


def test_constructor_raises_when_no_saved_credentials(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LPASS_HOME", str(tmp_path))

    with pytest.raises(Exception, match="Unable to create client"):
        LastpassClient()


def test_constructor_authenticates_and_saves_credentials(monkeypatch) -> None:
    authenticated = Mock()
    authenticator = Mock(return_value=authenticated)
    client = LastpassClient.__new__(LastpassClient)
    monkeypatch.setattr(client, "_get_config_home", lambda environ: Path("/tmp"))
    client._save_credentials = Mock()

    result = LastpassClient.__init__(
        client,
        username="user",
        password="password",
        mfa="123456",
        authenticator=authenticator,
    )

    assert result is None
    assert client.lastpass is authenticated
    authenticator.assert_called_once_with("user", "password", "123456")
    client._save_credentials.assert_called_once_with(authenticated)


def test_create_client_builds_lastpass_from_saved_credentials() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = None
    credentials = {
        "username": "user@example.com",
        "auth_response_data": {"iterations": 100},
        "vault_key": b"key",
        "vault_hash": b"hash",
        "session": Mock(),
    }
    created = Mock()
    client._create_client = Mock(return_value=created)

    result = client._create_client(**credentials)

    assert result is created
    client._create_client.assert_called_once_with(**credentials)


def test_get_secret_by_name_and_id_process_empty_results() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.get_secret_by_name.return_value = None
    client.lastpass.get_secret_by_id.return_value = None

    assert client.get_secret_by_name("Missing") == {}
    assert client.get_secret_by_id("123") == {}


def test_duplicate_and_edit_return_false_for_missing_secret() -> None:
    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.get_secret_by_name.return_value = None
    client.lastpass.get_secret_by_id.return_value = None

    assert client.duplicate_secret("Missing") is False
    assert client.edit_secret("Missing", notes="new") is False


def test_duplicate_generic_secure_note_uses_notes_field() -> None:
    class Secret:
        name = "Recovery"
        full_path = ""
        is_favorite = True
        notes = "backup codes"
        attribute_mapping: ClassVar = {}
        _data: ClassVar = {}

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.get_secret_by_name.return_value = Secret()
    client.create_typed_secure_note = Mock(return_value=True)

    assert client.duplicate_secret("Recovery") is True
    client.create_typed_secure_note.assert_called_once_with(
        name="Copy of Recovery",
        note_type="Generic",
        folder_path=None,
        fields={"Notes": "backup codes"},
        favorite=True,
    )


def test_edit_generic_secure_note_can_replace_notes() -> None:
    class Secret:
        name = "Recovery"
        full_path = "Personal"
        is_favorite = True
        notes = "old"
        attribute_mapping: ClassVar = {}
        _data: ClassVar = {}

        def delete(self):
            return True

    client = LastpassClient.__new__(LastpassClient)
    client.lastpass = Mock()
    client.lastpass.get_secret_by_name.return_value = Secret()
    client.create_typed_secure_note = Mock(return_value=True)

    assert client.edit_secret("Recovery", notes="new") is True
    client.create_typed_secure_note.assert_called_once_with(
        name="Recovery",
        note_type="Generic",
        folder_path="Personal",
        fields={"Notes": "new"},
        favorite=True,
    )


def test_change_password_rejects_short_password() -> None:
    client = LastpassClient.__new__(LastpassClient)

    with pytest.raises(ValueError, match="at least 8"):
        client.change_password("current", "short")
