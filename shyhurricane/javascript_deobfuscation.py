"""Shared JavaScript normalization without indexing or model imports."""

import logging
import os
import subprocess

from shyhurricane.command_image import unix_command_image
from shyhurricane.graph.parser_diagnostics import measured, remaining_seconds

logger = logging.getLogger(__name__)


@measured("normalization")
def deobfuscate_javascript(content: str, *, image=None) -> str:
    if not content:
        return content

    isolation = []
    if "_SHYHURRICANE_PARSE_CONTAINER" in os.environ:
        isolation = ["--name", os.environ["_SHYHURRICANE_PARSE_CONTAINER"], "--network=none", "--memory=3g"]
    docker_command = [
        "docker", "run", "--rm", *isolation, "-i", image or unix_command_image(),
        "timeout", "--preserve-status", "--kill-after=1m", "30m", "/usr/local/bin/jsdeobf.sh",
    ]
    logger.debug(f"Deobfuscating javascript with command {' '.join(docker_command)}")
    proc = subprocess.Popen(docker_command, universal_newlines=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    if "_SHYHURRICANE_PARSE_DEADLINE" in os.environ:
        try:
            result, _ = proc.communicate(content, timeout=max(0.001, remaining_seconds() / 2))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            subprocess.run(["docker", "rm", "-f", os.environ["_SHYHURRICANE_PARSE_CONTAINER"]],
                           capture_output=True, timeout=5, check=False)
            raise TimeoutError("JavaScript normalization deadline reached; original source retained")
        return result if proc.returncode == 0 and result.strip() else content
    result = ""
    try:
        proc.stdin.write(content)
        proc.stdin.close()
        while proc.poll() is None:
            line_out = proc.stdout.readline()
            if line_out:
                result += line_out
        # read any buffered output
        while True:
            line_out = proc.stdout.readline()
            if not line_out:
                break
            result += line_out
    except EOFError:
        pass

    return_code = proc.wait()
    if return_code != 0 or not result.strip():
        logger.warning("Deobfuscating javascript failed with exit code %d", return_code)
        return content
    else:
        logger.info("Deobfuscating javascript completed, from %d bytes to %d bytes", len(content), len(result))
        return result
