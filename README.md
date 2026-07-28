## cd-lastpass-cli

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
uv run cd-lastpass-cli --help
```

### Login

Provide the username and password as options or environment variables. If the
password or MFA code is omitted, the CLI prompts for it.

```sh
cd-lastpass-cli login --username user@example.com
```

```sh
LPASS_USERNAME=user@example.com LPASS_PASSWORD=secret LPASS_MFA=123456 \
  cd-lastpass-cli login
```

The MFA value is used only during login and is not saved.

Remove the saved session and vault keys from this machine:

```sh
cd-lastpass-cli logout
```

Generate a secure random password:

```sh
cd-lastpass-cli generate
cd-lastpass-cli generate --length 32
```

### Commands

Check the saved session:

```sh
cd-lastpass-cli status
```

List vault entries by name:

```sh
cd-lastpass-cli ls
```

Filter entries by group, include IDs, or return JSON:

```sh
cd-lastpass-cli ls --group Personal
cd-lastpass-cli ls --long
cd-lastpass-cli ls --json
```

Show an entry by name or ID:

```sh
cd-lastpass-cli show "Example Login"
cd-lastpass-cli show 123456789 --json
```

Delete an entry by name or ID. Deletion requires confirmation unless `--yes` is
provided:

```sh
cd-lastpass-cli delete "Example Login"
cd-lastpass-cli delete 123456789 --yes
```

Move an entry by name or ID to a different folder:

```sh
cd-lastpass-cli move "Example Login" --folder="Personal\Infrastructure"
```

Share an entry by name or ID with another LastPass user:

```sh
cd-lastpass-cli share "Example Login" user@example.com
```

Create entries with dynamically generated type-specific options. The available
types and fields come from `lastpasslib`:

```sh
cd-lastpass-cli create ssh-key \
  --name "Production SSH" \
  --hostname=prod.example.com \
  --private-key=@id_ed25519
```

Create a generic secure note or password entry:

```sh
cd-lastpass-cli create secure-note --name "Recovery Codes" --notes "..."
cd-lastpass-cli create password \
  --name "Example Login" \
  --url=https://example.com \
  --username=user@example.com \
  --password=secret
```

Use `--folder` to place an entry in a personal or shared-folder path:

```sh
cd-lastpass-cli create server \
  --name "Production" \
  --folder="Personal\Infrastructure" \
  --hostname=prod.example.com
```

Values beginning with `@` are read from a file, which supports multiline
fields such as private keys:

```sh
cd-lastpass-cli create ssh-key \
  --name "Production SSH" \
  --private-key=@~/.ssh/id_ed25519
```

Run `cd-lastpass-cli create --help` to list available entry types and
`cd-lastpass-cli create <type> --help` to list fields for a specific type.

Passwords are omitted by default. Include one explicitly when needed:

```sh
cd-lastpass-cli show "Example Login" --password
```

### Configuration and credentials

The default private data directory is `~/.lastpass-cli`. Set `LPASS_HOME` to
use another directory:

```sh
LPASS_HOME=/path/to/private-directory cd-lastpass-cli status
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
