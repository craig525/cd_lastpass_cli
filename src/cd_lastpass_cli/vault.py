from __future__ import annotations

import logging

import lastpasslib.lastpasslib
import lastpasslib.vault


class Vault(lastpasslib.vault.Vault):
    def __init__(self, *, lastpass_instance, key: bytes, hash: bytes):
        pass

    def __new__(cls, *, lastpass_instance, key: bytes, hash: bytes):
        vault = super().__new__(cls)
        vault._logger = logging.getLogger(
            f"{lastpasslib.vault.LOGGER_BASENAME}.{vault.__class__.__name__}"
        )
        vault._lastpass = lastpass_instance
        vault.username = lastpass_instance.username.encode("utf-8")
        vault._key = key
        vault._hash = hash
        vault._blob = None
        vault.key_iteration_count = lastpass_instance.iteration_count
        vault.unable_to_decrypt = []
        return vault
