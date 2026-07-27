from __future__ import annotations

import lastpasslib.lastpasslib
import lastpasslib.vault
from loguru import logger


class Vault(lastpasslib.vault.Vault):
    def __init__(
        self,
        lastpass_instance,
        password,
        *,
        key: bytes | None = None,
        hash: bytes | None = None,
    ):
        super().__init__(lastpass_instance, password)
        if key is not None:
            self._key = key
        if hash is not None:
            self._hash = hash

    @staticmethod
    def _parse_secure_note(data):
        secret_name = data.get("name")
        class_type, key_mapping = Vault._get_class_and_key_mapping(data)
        note_data = {"original_notes": data.get("notes", "")}
        try:
            current_entry = None
            current_value = []
            for line in data.get("notes").splitlines():
                key, separator, value = line.partition(":")
                entry = key_mapping.get(key) if separator else None
                if entry:
                    if current_entry:
                        note_data[current_entry] = "\n".join(current_value)
                    current_entry = entry
                    current_value = [value] if value else []
                elif current_entry:
                    current_value.append(line)
            if current_entry:
                note_data[current_entry] = "\n".join(current_value)
            data.update(note_data)
            if class_type == lastpasslib.vault.Custom:
                data["custom_attribute_mapping"] = key_mapping
        except TypeError:
            logger.error(
                f"Could not identify valid lines in the note of secret {secret_name} maybe it is corrupt?"
            )
        return class_type, data
    @staticmethod
    def _parse_secret_type(payload, encryption_key):
        """Parses an account chunk, decrypts and creates an Account object.

        All secure notes are ACCTs but not all of them store account information.
        """
        stream = lastpasslib.vault.Stream(payload)
        secret = lastpasslib.vault.SecretSchema()
        data = Vault._get_attribute_payload_data(stream, secret.attributes)
        data.update(Vault._transform_data_attributes(data,
                                                     secret.plain_encrypted,
                                                     lastpasslib.vault.EncryptManager.decrypt_aes256_auto,
                                                     arguments={'encryption_key': encryption_key}))
        data.update(Vault._transform_data_attributes(data,
                                                     secret.base_64_encrypted,
                                                     lastpasslib.vault.EncryptManager.decrypt_aes256_auto,
                                                     arguments={'encryption_key': encryption_key,
                                                                'base64': True}))
        data.update(Vault._transform_data_attributes(data,
                                                     secret.hex_decoded,
                                                     lastpasslib.vault.EncryptManager.try_decode,
                                                     arguments={"encryption_key": encryption_key}))

        data.update(Vault._transform_data_attributes(data,
                                                     secret.decoded_attributes,
                                                     #lambda x: x.decode("utf-8")))
                                                     lambda x: Vault._utf8_or_decrypt(x, encryption_key)))

        data.update(Vault._transform_data_attributes(data,
                                                     secret.boolean_values,
                                                     lambda x: bool(int(x))))
        data['encryption_key'] = encryption_key
        if data.get('is_secure_note'):
            return Vault._parse_secure_note(data)
        if all([not any([data.get('username'),
                         data.get('password'),
                         data.get('name'),
                         data.get('notes')]),
                data.get('url') == 'http://group']):
            return lastpasslib.vault.FolderEntry, data
        return lastpasslib.vault.Password, data

