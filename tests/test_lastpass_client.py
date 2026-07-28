from typing import ClassVar, cast
from unittest.mock import Mock

import lastpasslib.secrets

from cd_lastpass_cli.lastpass_client import Lastpass as LastpassType
from cd_lastpass_cli.lastpass_client import LastpassClient


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
