"""Optional diagnostic logging independent of the interactive dashboard."""

import logging
import os
import re
import threading
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


class Neo4jPropertyWarningFilter(logging.Filter):
    """Report each unknown property once per process, preserving other diagnostics."""

    def __init__(self):
        super().__init__()
        self.seen: set[str] = set()
        self.lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno != logging.WARNING:
            return True
        message = record.getMessage()
        if "gql_status='01N52'" not in message:
            return True
        match = re.search(r"The property `([^`]+)` does not exist in database", message)
        if match is None:
            return True
        property_name = match[1]
        with self.lock:
            if property_name in self.seen:
                return False
            self.seen.add(property_name)
        return True


def file_logging_enabled() -> bool:
    return any(isinstance(handler, DiagnosticFileHandler) for handler in logging.getLogger().handlers)


def set_console_logging_enabled(enabled: bool) -> None:
    _console_filter.enabled = enabled


def limit_neo4j_logging() -> None:
    """Avoid formatting full Bolt parameter payloads, including on existing child loggers."""
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    notifications = logging.getLogger("neo4j.notifications")
    if not any(isinstance(item, Neo4jPropertyWarningFilter) for item in notifications.filters):
        notifications.addFilter(Neo4jPropertyWarningFilter())
    for name, logger in logging.getLogger().manager.loggerDict.copy().items():
        if name.startswith("neo4j.") and isinstance(logger, logging.Logger):
            logger.setLevel(logging.WARNING)


def limit_http_client_logging() -> None:
    """Keep third-party HTTP request/response traces out of diagnostic logs."""
    http_loggers = ("httpx", "httpcore", "urllib3")
    for name in http_loggers:
        logging.getLogger(name).setLevel(logging.WARNING)
    for name, logger in logging.getLogger().manager.loggerDict.copy().items():
        if name.startswith(http_loggers) and isinstance(logger, logging.Logger):
            logger.setLevel(logging.WARNING)


def configure_file_logging(filename: str | None, console_enabled: bool = True) -> None:
    """Append diagnostics while limiting noisy driver and HTTP client logs to warnings.

    Worker processes inherit LOG_FILE and configure their own append handler. The file is
    opened before changing logging state so an invalid destination fails startup cleanly.
    """
    if not filename:
        limit_neo4j_logging()
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
    limit_neo4j_logging()
    limit_http_client_logging()
    set_console_logging_enabled(console_enabled)
    os.environ["LOG_FILE"] = str(path)
