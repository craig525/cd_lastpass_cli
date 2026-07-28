"""Extract and normalize data from LastPass secrets."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping
from typing import Any

import lastpasslib.datamodels
import lastpasslib.secrets

FieldProcessor = Callable[[Any], Any]

_FIELDS = {
    "type",
    "created_datetime",
    "is_deleted",
    "is_favorite",
    "group",
    "group_id",
    "full_path",
    "has_attachment",
    "has_been_shared",
    "id",
    "is_individual_share",
    "last_modified_datetime",
    "last_password_change_datetime",
    "is_secure_note",
    "last_touch_datetime",
    "name",
    "shared_folder",
    "notes",
    "username",
    "mfa_seed",
    "password",
}


def all_subclasses(cls: type) -> list[type]:
    subclasses = []
    for subclass in cls.__subclasses__():
        subclasses.append(subclass)
        subclasses.extend(all_subclasses(subclass))
    return subclasses


def secret_note_mappings() -> dict[str, Mapping[str, str]]:
    mappings = {}
    for secret_type in all_subclasses(lastpasslib.secrets.SecureNote):
        mapping = getattr(secret_type, "attribute_mapping", {})
        if isinstance(mapping, Mapping):
            mappings[secret_type.__name__] = mapping
    return mappings


def _add_secret_note_attributes():
    for mapping in secret_note_mappings().values():
        _FIELDS.update(mapping.values())


_add_secret_note_attributes()

_SENSITIVE_FIELDS = {
    "authentication",
    "mfa_seed",
    "passphrase",
    "password",
    "pin",
    "private_key",
    "security_code",
    "swift_code",
}


def _parse_shared_folder(value: Any) -> Any:
    if not isinstance(value, lastpasslib.datamodels.SharedFolder):
        if isinstance(value, str):
            return value
        return value

    data = dataclasses.asdict(value)
    if "share_data" in data:
        del data["share_data"]
    return data


FIELD_PROCESSORS: dict[str, FieldProcessor] = {
    "shared_folder": _parse_shared_folder,
}


def secret_data(secret: Any, include_password: bool = False) -> dict[str, Any]:
    data = {field: getattr(secret, field, None) for field in _FIELDS}
    # logger.info(dir(secret))
    # logger.info(secret.private_key)
    if not include_password:
        for field in _SENSITIVE_FIELDS:
            data.pop(field, None)
    return {key: value for key, value in data.items() if value is not None}


def process_secret_data(data: dict[str, Any]) -> dict[str, Any]:
    processed = dict(data)
    for field, processor in FIELD_PROCESSORS.items():
        if field in processed:
            processed[field] = processor(processed[field])
    return processed
