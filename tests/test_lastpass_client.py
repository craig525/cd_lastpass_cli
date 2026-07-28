from typing import cast
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
        attribute_mapping = {"Username": "username", "Notes": "notes"}
        username = "user"
        _data = {"note_type": "Email Account"}

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
