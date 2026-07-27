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
