"""Command-line interface for reading a LastPass vault."""

from __future__ import annotations

import csv
import json
import re
import secrets
import string
from pathlib import Path
from typing import Any

import click
import lastpasslib.secrets

from .exceptions import InvalidLastpassClientParams
from .lastpass_client import AuthenticatedLastpass, LastpassClient
from .logging_config import configure_logging
from .secret_data import all_subclasses

Lastpass = AuthenticatedLastpass


def _get_lastpass(ctx: click.Context) -> LastpassClient:
    if "lastpass" not in ctx.meta:
        try:
            ctx.meta["lastpass"] = LastpassClient()
        except InvalidLastpassClientParams as error:
            raise click.UsageError("No saved credentials; run login first.") from error
    return ctx.meta["lastpass"]


@click.group(context_settings={"auto_envvar_prefix": "LPASS"})
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Inspect a LastPass vault from the command line."""
    ctx.ensure_object(dict)


@cli.command("login")
@click.option(
    "--username",
    envvar="LPASS_USERNAME",
    show_envvar=True,
    required=True,
    help="LastPass username.",
)
@click.option("--password", envvar="LPASS_PASSWORD", hide_input=True, show_envvar=True)
@click.option(
    "--mfa",
    envvar="LPASS_MFA",
    show_envvar=True,
    help="One-time multifactor authentication code.",
)
def login(username: str, password: str | None, mfa: str | None) -> None:
    """Authenticate to LastPass."""
    if not password:
        password = click.prompt("Password", hide_input=True)
    if not mfa:
        mfa = click.prompt("MFA", default="", show_default=False)
    LastpassClient(username, password, mfa, authenticator=Lastpass)
    click.echo("Logged in")


@cli.command("logout")
def logout() -> None:
    """Remove saved LastPass credentials from this machine."""
    LastpassClient.logout()
    click.echo("Logged out")


@cli.command("passwd")
@click.pass_context
def passwd(ctx: click.Context) -> None:
    """Change the LastPass master password."""
    client = _get_lastpass(ctx)
    current_password = click.prompt("Current master password", hide_input=True)
    new_password = click.prompt("New master password", hide_input=True)
    confirmation = click.prompt("Confirm new master password", hide_input=True)
    if new_password != confirmation:
        raise click.ClickException("Passwords do not match.")
    try:
        client.change_password(current_password, new_password)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    click.echo("Password changed")


@cli.command("generate")
@click.option(
    "--length",
    type=click.IntRange(min=4, max=256),
    default=20,
    show_default=True,
    help="Password length.",
)
def generate(length: int) -> None:
    """Generate a secure random password."""
    character_sets = (
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    )
    password = [secrets.choice(characters) for characters in character_sets]
    alphabet = "".join(character_sets)
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    click.echo("".join(password))


@cli.command("status")
@click.pass_context
def status(ctx: click.Context) -> None:
    """Check whether credentials can authenticate to LastPass."""
    _get_lastpass(ctx)
    click.echo("Logged in")


@cli.command("sync")
@click.pass_context
def sync(ctx: click.Context) -> None:
    """Synchronize the local vault with LastPass."""
    if not _get_lastpass(ctx).sync():
        raise click.ClickException("Could not synchronize vault.")
    click.echo("Synchronized")


@cli.command("ls")
@click.option("--group", help="Only list entries in this group.")
@click.option("--long", "long_format", is_flag=True, help="Show entry details.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@click.pass_context
def list_entries(
    ctx: click.Context, group: str | None, long_format: bool, as_json: bool
) -> None:
    """List entries in the vault."""
    lastpass = _get_lastpass(ctx)
    secrets = lastpass.get_secrets_by_group(group) if group else lastpass.get_secrets()
    if as_json:
        click.echo(json.dumps(secrets, default=str))
        return
    for secret in secrets:
        click.echo(
            secret["name"] if not long_format else f"{secret['id']}\t{secret['name']}"
        )


@cli.command("export")
@click.argument("path", type=click.Path(dir_okay=False, writable=True, path_type=Path))
@click.option("--group", help="Only export entries in this group.")
@click.option("--password", "include_password", is_flag=True, help="Include passwords.")
@click.pass_context
def export_entries(
    ctx: click.Context, path: Path, group: str | None, include_password: bool
) -> None:
    """Export vault entries to a CSV file."""
    lastpass = _get_lastpass(ctx)
    secrets = (
        lastpass.get_secrets_by_group(group, include_password=include_password)
        if group
        else lastpass.get_secrets(include_password=include_password)
    )
    fieldnames = sorted({field for secret in secrets for field in secret})
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(secrets)
    click.echo(path)


@cli.command("show")
@click.argument("name")
@click.option(
    "--password", "include_password", is_flag=True, help="Include the password."
)
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@click.pass_context
def show(ctx: click.Context, name: str, include_password: bool, as_json: bool) -> None:
    """Show an entry by name or ID."""
    lastpass = _get_lastpass(ctx)
    secret = lastpass.get_secret_by_name(
        name, include_password=include_password
    ) or lastpass.get_secret_by_id(name, include_password=include_password)
    if secret is None:
        raise click.ClickException(f"Entry not found: {name}")
    if as_json:
        click.echo(json.dumps(secret, sort_keys=True, default=str))
        return
    for key, value in secret.items():
        click.echo(f"{key}: {value}")


@cli.command("delete")
@click.argument("name_or_id")
@click.confirmation_option(
    "--yes", prompt="Are you sure you want to delete this entry?"
)
@click.pass_context
def delete(ctx: click.Context, name_or_id: str) -> None:
    """Delete an entry by name or ID."""
    if not _get_lastpass(ctx).delete_secret(name_or_id):
        raise click.ClickException(f"Entry not found: {name_or_id}")
    click.echo(name_or_id)


@cli.command("move")
@click.argument("name_or_id")
@click.option("--folder", "folder_path", required=True, help="Destination folder path.")
@click.pass_context
def move(ctx: click.Context, name_or_id: str, folder_path: str) -> None:
    """Move an entry to a different folder."""
    if not _get_lastpass(ctx).move_secret(name_or_id, folder_path):
        raise click.ClickException(f"Could not move entry: {name_or_id}")
    click.echo(name_or_id)


@cli.command("share")
@click.argument("name_or_id")
@click.argument("email")
@click.pass_context
def share(ctx: click.Context, name_or_id: str, email: str) -> None:
    """Share an entry with another LastPass user."""
    if not _get_lastpass(ctx).share_secret(name_or_id, email):
        raise click.ClickException(f"Could not share entry: {name_or_id}")
    click.echo(name_or_id)


@cli.command("duplicate")
@click.argument("name_or_id")
@click.option("--name", help="Name for the duplicate entry.")
@click.pass_context
def duplicate(ctx: click.Context, name_or_id: str, name: str | None) -> None:
    """Duplicate an entry by name or ID."""
    duplicate_name = name or f"Copy of {name_or_id}"
    if not _get_lastpass(ctx).duplicate_secret(name_or_id, name):
        raise click.ClickException(f"Entry not found: {name_or_id}")
    click.echo(duplicate_name)


def _command_name(value: str) -> str:
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", value)
    return re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()


def _field_option_name(label: str) -> str:
    return _command_name(label)


def _read_at_value(value: str) -> str:
    if not value.startswith("@"):
        return value
    try:
        return Path(value[1:]).read_text()
    except OSError as error:
        raise click.ClickException(f"Could not read field file {value[1:]}") from error


@cli.group("create")
def create() -> None:
    """Create a vault entry."""


@create.command("password")
@click.option("--name", required=True)
@click.option("--folder", "folder_path")
@click.option("--url")
@click.option("--username")
@click.option("--password", hide_input=True)
@click.option("--totp")
@click.option("--notes")
@click.option("--favorite", is_flag=True)
@click.pass_context
def create_password(
    ctx: click.Context,
    name: str,
    folder_path: str | None,
    url: str | None,
    username: str | None,
    password: str | None,
    totp: str | None,
    notes: str | None,
    favorite: bool,
) -> None:
    """Create a password entry."""
    _get_lastpass(ctx).create_password(
        name=name,
        folder_path=folder_path,
        url=url,
        username=username,
        password=password,
        totp=totp,
        notes=notes,
        favorite=favorite,
    )
    click.echo(name)


def _create_secure_note_command(note_type: str, field_labels: dict[str, str]):
    def command(ctx: click.Context, **kwargs: Any) -> None:
        fields = {
            field_labels[field]: _read_at_value(value)
            for field, value in kwargs.items()
            if field in field_labels and value is not None
        }
        folder_path = kwargs.pop("folder_path")
        favorite = kwargs.pop("favorite")
        name = kwargs.pop("name")
        _get_lastpass(ctx).create_typed_secure_note(
            name=name,
            note_type=note_type,
            folder_path=folder_path,
            fields=fields,
            favorite=favorite,
        )
        click.echo(name)

    command.__name__ = f"create_{_command_name(note_type)}"
    command.__doc__ = f"Create a {note_type} secure note."
    decorated = click.pass_context(command)
    for field in reversed(field_labels):
        option_name = _field_option_name(field)
        decorated = click.option(f"--{option_name}", option_name.replace("-", "_"))(
            decorated
        )
    decorated = click.option("--favorite", is_flag=True)(decorated)
    decorated = click.option("--folder", "folder_path")(decorated)
    decorated = click.option("--name", required=True)(decorated)
    return click.command(_command_name(note_type))(decorated)


_note_types = {"SecureNote": "Generic"}
_note_types.update(
    {
        secret_type.__name__: note_type
        for note_type, secret_type in lastpasslib.secrets.SECRET_NOTE_CLASS_MAPPING.items()
    }
)
for _secret_type in [
    lastpasslib.secrets.SecureNote,
    *all_subclasses(lastpasslib.secrets.SecureNote),
]:
    if _secret_type.__name__ == "Generic":
        continue
    _note_type = _note_types.get(_secret_type.__name__)
    if _note_type is None:
        continue
    _mapping = getattr(_secret_type, "attribute_mapping", {})
    if not hasattr(_mapping, "items"):
        _mapping = {}
    _labels = {_field_option_name(label).replace("-", "_"): label for label in _mapping}
    command = _create_secure_note_command(_note_type, _labels)
    if _secret_type is lastpasslib.secrets.SecureNote:
        command.name = "secure-note"
    create.add_command(command)


def main() -> None:
    """Run the command-line interface."""
    configure_logging()
    cli()
