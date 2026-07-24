from __future__ import annotations

import inspect
import logging
import os
from collections.abc import Mapping
from pathlib import Path

from loguru import logger


class InterceptHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        frame, depth = inspect.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1
        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)


def configure_logging(environ: Mapping[str, str] | None = None) -> Path:
    """Configure a private rotating Loguru file sink."""
    environ = os.environ if environ is None else environ
    directory = Path(environ.get("LPASS_HOME", "~/.lastpass-cli")).expanduser()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    log_path = directory / "cd-lastpass-cli.log"
    logger.remove()
    logger.add(log_path, rotation="10 MB", retention=3, level="INFO")
    return log_path
