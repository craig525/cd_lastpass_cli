from datetime import UTC, datetime

from cd_lastpass_cli.secret_data import process_secret_data, secret_data


def test_shared_folder_is_processed_into_structured_data() -> None:
    class Secret:
        shared_folder = (
            "id: 620662516\n"
            "name: DevOps\n"
            "read_only: 0\n"
            "deleted: 0\n"
            "created: 2026-07-21 12:29:02\n"
            "last_modified: 2026-07-21 12:29:02\n"
            "sharer: Shared-DevOps\n"
        )

    data = process_secret_data(secret_data(Secret()))

    assert data["shared_folder"] == {
        "id": 620662516,
        "name": "DevOps",
        "read_only": False,
        "deleted": False,
        "created": datetime(2026, 7, 21, 12, 29, 2, tzinfo=UTC),
        "last_modified": datetime(2026, 7, 21, 12, 29, 2, tzinfo=UTC),
        "sharer": "Shared-DevOps",
    }
