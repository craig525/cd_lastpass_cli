## lastpass

A small command-line interface for authenticating to LastPass and inspecting
vault entries.

Requires Python 3.12 or newer.

### Install

Install the package with `uv`:

```sh
uv tool install .
```

For development, create the project environment and install the dependencies:

```sh
uv sync
uv run lastpass --help
```

### Login

Provide the username and password as options or environment variables. If the
password or MFA code is omitted, the CLI prompts for it.

```sh
lastpass login --username user@example.com
```

```sh
LPASS_USERNAME=user@example.com LPASS_PASSWORD=secret LPASS_MFA=123456 \
  lastpass login
```

The MFA value is used only during login and is not saved.

Remove the saved session and vault keys from this machine:

```sh
lastpass logout
```

Change the LastPass master password and re-encrypt the vault:

```sh
lastpass passwd
```

Generate a secure random password:

```sh
lastpass generate
lastpass generate --length 32
```

### Commands

Check the saved session:

```sh
lastpass status
```

Synchronize the local vault with LastPass:

```sh
lastpass sync
```

List vault entries by name:

```sh
lastpass ls
```

Filter entries by group, include IDs, or return JSON:

```sh
lastpass ls --group Personal
lastpass ls --long
lastpass ls --json
```

Export vault entries to CSV. Passwords are omitted unless `--password` is
explicitly provided:

```sh
lastpass export vault.csv
lastpass export personal.csv --group Personal --password
```

Import entries from a LastPass CSV export:

```sh
lastpass import vault.csv
```

Show an entry by name or ID:

```sh
lastpass show "Example Login"
lastpass show 123456789 --json
```

Delete an entry by name or ID. Deletion requires confirmation unless `--yes` is
provided:

```sh
lastpass delete "Example Login"
lastpass delete 123456789 --yes
```

Move an entry by name or ID to a different folder:

```sh
lastpass move "Example Login" --folder="Personal\Infrastructure"
```

Share an entry by name or ID with another LastPass user:

```sh
lastpass share "Example Login" user@example.com
```

Create entries with dynamically generated type-specific options. The available
types and fields come from `lastpasslib`:

```sh
lastpass create ssh-key \
  --name "Production SSH" \
  --hostname=prod.example.com \
  --private-key=@id_ed25519
```

Create a generic secure note or password entry:

```sh
lastpass create secure-note --name "Recovery Codes" --notes "..."
lastpass create password \
  --name "Example Login" \
  --url=https://example.com \
  --username=user@example.com \
  --password=secret
```

Use `--folder` to place an entry in a personal or shared-folder path:

```sh
lastpass create server \
  --name "Production" \
  --folder="Personal\Infrastructure" \
  --hostname=prod.example.com
```

Values beginning with `@` are read from a file, which supports multiline
fields such as private keys:

```sh
lastpass create ssh-key \
  --name "Production SSH" \
  --private-key=@~/.ssh/id_ed25519
```

Run `lastpass create --help` to list available entry types and
`lastpass create <type> --help` to list fields for a specific type.

Passwords are omitted by default. Include one explicitly when needed:

```sh
lastpass show "Example Login" --password
```

### Configuration and credentials

The default private data directory is `~/.lastpass-cli`. Set `LPASS_HOME` to
use another directory:

```sh
LPASS_HOME=/path/to/private-directory lastpass status
```

After a successful login, the CLI saves the authenticated session and vault
keys in that directory so subsequent commands do not require another login.
The directory is created with mode `0700`; saved files use mode `0600`.
Treat this directory as sensitive because it contains reusable authentication
data. Delete it to clear the saved session and log in again.

Operational logs are written to `cd-lastpass-cli.log` in the same directory,
with rotation at 10 MB and retention of three files.

### Development

Run the test suite and checks with:

```sh
uv run pytest
uv run ruff check .
uv run ty check
```

### Publishing

Update the package version before each release. This updates `pyproject.toml`
and the lockfile:

```sh
uv version 0.2.0
```

Run the checks, build the source distribution and wheel, and inspect the
artifacts:

```sh
uv run ruff check .
uv run ty check
uv run pytest
uv build --no-sources
ls dist/
```

Publish the artifacts to PyPI with a PyPI API token. Keep the token out of the
repository and shell history by exporting it through the environment:

```sh
export UV_PUBLISH_TOKEN=pypi-...
uv publish
```

After publishing, verify that the package can be installed from PyPI:

```sh
uv tool install --refresh cd-lastpass-cli
lastpass --help
```
