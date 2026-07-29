from unittest.mock import Mock

import pytest

from cd_lastpass_cli.vault import Vault


def test_vault_accepts_original_arguments_and_state_overrides() -> None:
    class Lastpass:
        username = "user@example.com"
        iteration_count = 100

    key = b"vault key"
    vault_hash = b"vault hash"

    vault = Vault(Lastpass(), "password", key=key, hash=vault_hash)

    assert vault.username == b"user@example.com"
    assert vault.password == b"password"
    assert vault.key == key
    assert vault.hash == vault_hash


def test_parse_secure_note_preserves_newlines_in_values() -> None:
    data = {
        "name": "SSH key",
        "note_type": "SSH Key",
        "notes": (
            "Private Key:-----BEGIN PRIVATE KEY-----\n"
            "key contents\n"
            "-----END PRIVATE KEY-----\n"
            "Hostname:host.example.com:22\n"
        ),
    }

    _, parsed = Vault._parse_secure_note(data)

    assert parsed["private_key"] == (
        "-----BEGIN PRIVATE KEY-----\nkey contents\n-----END PRIVATE KEY-----"
    )
    assert parsed["hostname"] == "host.example.com:22"


def test_parse_secure_note_handles_multiline_value_after_empty_value() -> None:
    data = {
        "name": "SSH key",
        "note_type": "SSH Key",
        "notes": (
            "Private Key:\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "key contents\n"
            "-----END PRIVATE KEY-----\n"
            "Hostname:host.example.com\n"
        ),
    }

    _, parsed = Vault._parse_secure_note(data)

    assert parsed["private_key"] == (
        "-----BEGIN PRIVATE KEY-----\nkey contents\n-----END PRIVATE KEY-----"
    )


def test_parse_secure_note_adds_custom_attribute_mapping() -> None:
    data = {
        "name": "Custom note",
        "note_type": "Custom note",
        "custom_note_definition_json": '{"fields": [{"text": "Account"}, {"text": "Details"}]}',
        "notes": "Account:one\nDetails:two",
    }

    class_type, parsed = Vault._parse_secure_note(data)

    assert class_type.__name__ == "Custom"
    assert parsed["custom_attribute_mapping"] == {
        "Account": "account",
        "Details": "details",
    }


def test_parse_secure_note_rejects_missing_notes() -> None:
    data = {"name": "Corrupt note", "note_type": "SSH Key"}

    with pytest.raises(AttributeError):
        Vault._parse_secure_note(data)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"is_secure_note": False, "url": "http://group"}, "FolderEntry"),
        (
            {"is_secure_note": False, "url": "https://example.com", "name": "Entry"},
            "Password",
        ),
    ],
)
def test_parse_secret_type_classifies_folder_and_password(
    monkeypatch, data, expected
) -> None:
    monkeypatch.setattr(
        Vault, "_get_attribute_payload_data", Mock(return_value=data.copy())
    )
    monkeypatch.setattr(Vault, "_transform_data_attributes", Mock(return_value={}))

    class_type, parsed = Vault._parse_secret_type(b"payload", b"key")

    assert class_type.__name__ == expected
    assert parsed["encryption_key"] == b"key"


def test_parse_secret_type_delegates_secure_notes(monkeypatch) -> None:
    data = {"is_secure_note": True, "name": "Note"}
    monkeypatch.setattr(
        Vault, "_get_attribute_payload_data", Mock(return_value=data.copy())
    )
    monkeypatch.setattr(Vault, "_transform_data_attributes", Mock(return_value={}))
    parsed = (object, {"parsed": True})
    parse_secure_note = Mock(return_value=parsed)
    monkeypatch.setattr(Vault, "_parse_secure_note", parse_secure_note)

    result = Vault._parse_secret_type(b"payload", b"key")

    assert result == parsed
    parse_secure_note.assert_called_once()
