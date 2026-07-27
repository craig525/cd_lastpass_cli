from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NamedTuple

import dill as pickle
import lastpasslib.lastpasslib
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


class LastpassClient:
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
