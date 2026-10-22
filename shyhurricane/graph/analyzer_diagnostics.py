"""Bounded subprocess diagnostics without echoed JavaScript inputs."""

import re


def stderr_summary(stderr, source):
    """Retain error headings and stack frames, omitting source excerpts and URL secrets."""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    source_lines = {line.strip() for line in source.splitlines()}
    lines = []
    for line in (stderr or "").splitlines():
        stripped = line.strip()
        if stripped in source_lines or not stripped or set(stripped) <= {"^", "~"}:
            continue
        # Node/Babel source excerpts, including numbered code frames, can contain credentials.
        if re.match(r"[>\s]*\d+\s*\|", line):
            continue
        if not (re.match(r"(?:\w*Error|Error|docker:|node:|Caused by:)", stripped)
                or stripped.startswith("at ")):
            continue
        line = re.sub(r"https?://[^\s)]+", "[url omitted]", line)
        line = re.sub(r"(?i)(token|password|secret|authorization|cookie)\s*[:=]\s*\S+", r"\1=[redacted]", line)
        # Parser messages can quote captured identifiers or source fragments.
        line = re.sub(r"(['\"`]).*?\1", "[quoted text omitted]", line)
        lines.append(line)
    summary = "\n".join(lines) or "[stderr empty or omitted: no safe diagnostic lines]"
    return summary[:4096] + (" [truncated]" if len(summary) > 4096 else "")
