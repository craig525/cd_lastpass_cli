# Agent Instructions

## Project Shape

- This is a single Python package under `src/cd_lastpass_cli`; the console entrypoint is `cd-lastpass-cli = cd_lastpass_cli:main` in `pyproject.toml`.
- The CLI wraps `lastpasslib` and persists reusable session and vault key material under `LPASS_HOME` or `~/.lastpass-cli`; never use real credentials or a real LastPass home for tests.
- `login` authenticates and writes saved credentials; `status`, `ls`, and `show` reload them. `show` omits passwords unless `--password` is explicitly passed.

## Development Commands

- Use Python 3.12+ and `uv`; run `uv sync` before development commands.
- Run tests with `uv run pytest`.
- Run lint with `uv run ruff check .`.
- Run type checking with `uv run ty check`.
- The repository has no CI, pre-commit, formatter, or task-runner configuration; do not infer additional required checks.

## Testing

- Tests use `pytest` and Click's `CliRunner`; authentication is mocked in tests, so preserve that pattern rather than making network calls.
- Tests that exercise credential persistence should set `HOME` or `LPASS_HOME` to a temporary directory; persisted files are expected to be mode `0600` and the directory mode `0700`.

## Sensitive Runtime Data

- `LPASS_HOME` contains saved authentication data and the rotating `cd-lastpass-cli.log`; treat it as sensitive and avoid printing or committing its contents.
- The CLI's default log sink is `cd-lastpass-cli.log` in `LPASS_HOME`, rotated at 10 MB with three retained files.
