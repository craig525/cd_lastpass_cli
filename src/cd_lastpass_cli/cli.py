"""Command-line interface for reading a LastPass vault."""

from __future__ import annotations

import json
from typing import Any

import click
import lastpasslib
import lastpasslib.secrets

from .exceptions import InvalidLastpassClientParams
from .lastpass_client import AuthenticatedLastpass, LastpassClient
from .logging_config import configure_logging

Lastpass = AuthenticatedLastpass


def _get_lastpass(ctx: click.Context) -> LastpassClient:
    if "lastpass" not in ctx.meta:
        try:
            ctx.meta["lastpass"] = LastpassClient()
        except InvalidLastpassClientParams as error:
            raise click.UsageError("No saved credentials; run login first.") from error
    return ctx.meta["lastpass"]


def _secret_data(secret: Any, include_password: bool = False) -> dict[str, Any]:
    fields = {'type', 'created_datetime', 'is_deleted', 'is_favorite', 'group', 'group_id', 'full_path', 'has_attachment', 'has_been_shared', 'id', 'is_individual_share', 'last_modified_datetime', 'last_password_change_datetime', 'is_secure_note', 'last_touch_datetime', 'name', 'shared_folder', "notes", "username", "mfa_seed", "password"}

    for s in dir(lastpasslib.secrets):
        fields.update(getattr(s, 'attribute_mapping', []))
    data = {}
    for field in fields:
        data[field] = getattr(secret, field, None)

    if not include_password and "password" in data:
        del data["password"]
    return {key: value for key, value in data.items() if value is not None}


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


@cli.command("status")
@click.pass_context
def status(ctx: click.Context) -> None:
    """Check whether credentials can authenticate to LastPass."""
    _get_lastpass(ctx)
    click.echo("Logged in")


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
    secrets = (
        lastpass.lastpass.get_secrets_by_group(group)
        if group
        else lastpass.lastpass.get_secrets()
    )
    data = [_secret_data(secret) for secret in secrets]
    if as_json:
        click.echo(json.dumps(data, default=str))
        return
    for secret in data:
        click.echo(
            secret["name"] if not long_format else f"{secret['id']}\t{secret['name']}"
        )


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
    secret = lastpass.lastpass.get_secret_by_name(
        name
    ) or lastpass.lastpass.get_secret_by_id(name)
    if secret is None:
        raise click.ClickException(f"Entry not found: {name}")
    data = _secret_data(secret, include_password)
    if as_json:
        click.echo(json.dumps(data))
        return
    for key, value in data.items():
        click.echo(f"{key}: {value}")


def main() -> None:
    """Run the command-line interface."""
    configure_logging()
    cli()
