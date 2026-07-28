from typing import cast

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
