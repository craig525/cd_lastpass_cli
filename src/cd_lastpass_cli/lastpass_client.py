from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
from collections.abc import Mapping
from functools import partial
from pathlib import Path
from typing import Any, NamedTuple, cast

import dill as pickle
import lastpasslib.configuration
import lastpasslib.encryption
import lastpasslib.lastpasslib
import lastpasslib.secrets
import requests
from loguru import logger

from .exceptions import InvalidLastpassClientParams, NoSavedCredentials
from .secret_data import process_secret_data, secret_data
from .vault import Vault


class SavedCredentials(NamedTuple):
    username: str
    auth_response_data: dict[str, Any]
    session: requests.Session
    vault_key: bytes
    vault_hash: bytes


class AuthenticatedLastpass(lastpasslib.lastpasslib.Lastpass):
    def __del__(self):
        return True


class Lastpass(AuthenticatedLastpass):
    def __init__(
        self,
        *,
        username,
        auth_response_data,
        session,
        vault_key,
        vault_hash,
        domain="lastpass.com",
    ):
        pass

    def __new__(
        cls,
        *,
        username,
        auth_response_data,
        session,
        vault_key,
        vault_hash,
        domain="lastpass.com",
    ):
        lastpass = super().__new__(cls)
        lastpass._logger = logging.getLogger(
            f"{lastpasslib.lastpasslib.LOGGER_BASENAME}.{lastpass.__class__.__name__}"
        )
        lastpass.domain = domain
        lastpass.host = f"https://{domain}"
        lastpass.show_endpoint = f"{lastpass.host}/show.php"
        lastpass.api_endpoint = f"{lastpass.host}/lastpass/api.php"
        lastpass.username = username
        lastpass._iteration_count = auth_response_data.get("iterations")
        lastpass._authenticated_response_data = auth_response_data
        lastpass.session = session
        lastpass._shared_folders_data_ = None
        lastpass._folders = None
        lastpass._decrypted_vault = None
        lastpass._vault = Vault(lastpass, "", key=vault_key, hash=vault_hash)
        return lastpass

    def create_typed_secure_note(
        self,
        name: str,
        note_type: str,
        folder_path: str | None = None,
        fields: Mapping[str, str] | None = None,
        favorite: bool = False,
    ) -> bool:
        if (
            note_type not in lastpasslib.secrets.SECRET_NOTE_CLASS_MAPPING
            and note_type != "Generic"
        ):
            raise ValueError(f"Unknown secure note type: {note_type}")
        base_folder = self._get_base_folder_by_path(folder_path or "")
        grouping = self._get_grouping_by_folder_path(
            folder_path or "", base_folder.is_personal
        )
        fields = dict(fields or {})
        notes = "\n".join(
            f"{field}:{value}" for field, value in fields.items() if value is not None
        )
        encrypt_and_encode = partial(
            lastpasslib.encryption.EncryptManager.encrypt_and_encode_payload,
            base_folder.encryption_key,
        )
        remote_payload = {
            "encuser": urllib.parse.quote(self.encrypted_username, safe=""),
            "extra": encrypt_and_encode(notes),
            "fav": "on" if favorite else "",
            "grouping": encrypt_and_encode(grouping),
            "hexName": name.encode("utf-8").hex(),
            "n": name.encode("utf-8").hex(),
            "name": encrypt_and_encode(name),
            "notetype": note_type,
            "requesthash": urllib.parse.quote(self.encrypted_username, safe=""),
            "sentms": f"{time.time_ns() // 1_000_000}",
            "sharedfolderid": "" if base_folder.is_personal else base_folder.id,
            "token": urllib.parse.quote(self.csrf_token, safe=""),
        }
        remote_payload = dict(
            lastpasslib.configuration.Configurations.secure_note_payload,
            **remote_payload,
        )
        parsed_response = self._create_secret(  # type: ignore[arg-type]
            lastpasslib.secrets.SecureNote, name, remote_payload
        )
        result = parsed_response.find("result")
        secret_id = result.attrib.get("aid")
        if not secret_id:
            raise lastpasslib.lastpasslib.UnknownAccountID
        secret_class = lastpasslib.secrets.SECRET_NOTE_CLASS_MAPPING.get(
            note_type, lastpasslib.secrets.SecureNote
        )
        local_payload = {
            "type": secret_class,
            "encryption_key": base_folder.encryption_key,
            "is_favorite": favorite,
            "group": grouping,
            "group_id": base_folder.id,
            "id": secret_id,
            "name": name,
            "note_type": note_type,
            "notes": notes,
            "created_gmt": int(time.time()),
            "shared_folder_id": None if base_folder.is_personal else base_folder.id,
        }
        mapping = getattr(secret_class, "attribute_mapping", {})
        if hasattr(mapping, "items"):
            local_payload.update(
                {
                    attribute: fields[label]
                    for label, attribute in mapping.items()
                    if label in fields
                }
            )
        return self.decrypted_vault.create_secret(local_payload["type"], local_payload)


class LastpassClient:
    _CREDENTIAL_FILES = (
        "_response_data",
        "_vault_hash",
        "_vault_key",
        "_session",
        "_username",
    )

    def __init__(
        self,
        username=None,
        password=None,
        mfa=None,
        *,
        authenticator=AuthenticatedLastpass,
    ):
        self._config_home = self._get_config_home(os.environ)
        lastpass = None
        if username and password and mfa:
            logger.info("Authenticating LastPass user {}", username)
            lastpass = authenticator(username, password, mfa)
        else:
            try:
                credentials = self._load_credentials()
                lastpass = self._create_client(
                    username=credentials.username,
                    session=credentials.session,
                    vault_hash=credentials.vault_hash,
                    vault_key=credentials.vault_key,
                    auth_response_data=credentials.auth_response_data,
                )
            except NoSavedCredentials:
                logger.debug("No saved LastPass credentials found")
        if not lastpass:
            raise InvalidLastpassClientParams("Unable to create client")
        self.lastpass = lastpass
        self._save_credentials(self.lastpass)

    def _get_config_home(self, environ: Mapping[str, str] | None = None) -> Path:
        environ = os.environ if environ is None else environ
        path = Path(environ.get("LPASS_HOME", "~/.lastpass-cli")).expanduser()
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
        return path

    @classmethod
    def logout(cls, environ: Mapping[str, str] | None = None) -> None:
        environ = os.environ if environ is None else environ
        config_home = Path(environ.get("LPASS_HOME", "~/.lastpass-cli")).expanduser()
        for filename in cls._CREDENTIAL_FILES:
            try:
                (config_home / filename).unlink()
            except FileNotFoundError:
                continue

    def _save_credentials(self, lastpass) -> None:
        files = {
            "_response_data": (
                json.dumps(lastpass._authenticated_response_data),
                False,
            ),
            "_vault_hash": (pickle.dumps(lastpass._vault.hash), True),
            "_vault_key": (pickle.dumps(lastpass._vault.key), True),
            "_session": (pickle.dumps(lastpass.session), True),
            "_username": (json.dumps(lastpass.username), False),
        }
        for name, (content, binary) in files.items():
            path = self._config_home / name
            if binary:
                path.write_bytes(content)
            else:
                path.write_text(content)
            path.chmod(0o600)

    def _create_client(
        self, *, username, auth_response_data, vault_key, vault_hash, session
    ):
        logger.info("Creating lastpass client from saved credentials")
        return Lastpass(
            username=username,
            auth_response_data=auth_response_data,
            session=session,
            vault_key=vault_key,
            vault_hash=vault_hash,
        )

    def _load_credentials(self) -> SavedCredentials:
        try:
            return SavedCredentials(
                username=json.loads((self._config_home / "_username").read_text()),
                auth_response_data=json.loads(
                    (self._config_home / "_response_data").read_text()
                ),
                session=pickle.loads((self._config_home / "_session").read_bytes()),
                vault_key=pickle.loads((self._config_home / "_vault_key").read_bytes()),
                vault_hash=pickle.loads(
                    (self._config_home / "_vault_hash").read_bytes()
                ),
            )
        except (OSError, ValueError, pickle.UnpicklingError, EOFError, TypeError):
            logger.exception("Error loading credentials")
            raise NoSavedCredentials from None

    def get_secrets(
        self, include_password: bool = False, filter_=None
    ) -> list[dict[str, Any]]:
        return [
            process_secret_data(secret_data(s, include_password=include_password))
            for s in self.lastpass.get_secrets(filter_=filter_)
        ]

    def get_secrets_by_group(
        self, group_name, include_password: bool = False, filter_=None
    ) -> list[dict[str, Any]]:
        return [
            process_secret_data(secret_data(s, include_password=include_password))
            for s in self.lastpass.get_secrets_by_group(
                group_name=group_name, filter_=filter_
            )
        ]

    def get_secret_by_name(self, name, include_password: bool = False):
        return process_secret_data(
            secret_data(
                self.lastpass.get_secret_by_name(name),
                include_password=include_password,
            )
        )

    def get_secret_by_id(self, id_, include_password: bool = False):
        return process_secret_data(
            secret_data(
                self.lastpass.get_secret_by_id(id_), include_password=include_password
            )
        )

    def delete_secret(self, name_or_id: str) -> bool:
        secret = self.lastpass.get_secret_by_name(name_or_id)
        if secret is None:
            secret = self.lastpass.get_secret_by_id(name_or_id)
        if secret is None:
            return False
        return secret.delete()

    def move_secret(self, name_or_id: str, folder_path: str) -> bool:
        secret = self.lastpass.get_secret_by_name(name_or_id)
        if secret is None:
            secret = self.lastpass.get_secret_by_id(name_or_id)
        if secret is None:
            return False
        return secret.move_to_folder(folder_path)

    def create_password(self, **fields: Any) -> bool:
        return cast(Lastpass, self.lastpass).create_password(**fields)

    def create_typed_secure_note(self, **fields: Any) -> bool:
        return cast(Lastpass, self.lastpass).create_typed_secure_note(**fields)
