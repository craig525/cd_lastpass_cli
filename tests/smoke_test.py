from cd_lastpass_cli import cli

try:
    cli(["--help"])
except SystemExit as error:
    assert error.code == 0
