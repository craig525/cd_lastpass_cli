"""Command-line interface for reading a LastPass vault."""

from __future__ import annotations

import json

import click

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
    secrets = lastpass.get_secrets_by_group(group) if group else lastpass.get_secrets()
    if as_json:
        click.echo(json.dumps(secrets, default=str))
        return
    for secret in secrets:
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


def main() -> None:
    """Run the command-line interface."""
    configure_logging()
    cli()
