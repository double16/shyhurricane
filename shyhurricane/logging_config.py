"""Optional diagnostic logging independent of the interactive dashboard."""

import logging
import os
from pathlib import Path


class DiagnosticFileHandler(logging.FileHandler):
    """Identify the application's file handler when logging is configured again."""


class ConsoleFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.enabled = True

    def filter(self, record: logging.LogRecord) -> bool:
        return self.enabled


_console_filter = ConsoleFilter()


def file_logging_enabled() -> bool:
    return any(isinstance(handler, DiagnosticFileHandler) for handler in logging.getLogger().handlers)


def set_console_logging_enabled(enabled: bool) -> None:
    _console_filter.enabled = enabled


def configure_file_logging(filename: str | None, console_enabled: bool = True) -> None:
    """Append all Python logger levels to a UTF-8 file, including exception details.

    Worker processes inherit LOG_FILE and configure their own append handler. The file is
    opened before changing logging state so an invalid destination fails startup cleanly.
    """
    if not filename:
        return
    path = Path(filename).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = DiagnosticFileHandler(path, mode="a", encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(processName)s:%(process)d] %(message)s")
    )
    root = logging.getLogger()
    for previous in root.handlers[:]:
        if isinstance(previous, DiagnosticFileHandler):
            root.removeHandler(previous)
            previous.close()
    if not any(
        isinstance(existing, logging.StreamHandler) and not isinstance(existing, logging.FileHandler)
        for existing in root.handlers
    ):
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        root.addHandler(console)
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    logging.disable(logging.NOTSET)
    loggers = [root, *[value for value in root.manager.loggerDict.values() if isinstance(value, logging.Logger)]]
    for logger in loggers:
        logger.setLevel(logging.DEBUG)
        logger.disabled = False
        logger.propagate = True
        for existing in logger.handlers:
            if isinstance(existing, logging.StreamHandler) and not isinstance(existing, logging.FileHandler):
                existing.addFilter(_console_filter)
    set_console_logging_enabled(console_enabled)
    os.environ["LOG_FILE"] = str(path)
