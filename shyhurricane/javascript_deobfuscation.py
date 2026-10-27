"""Shared JavaScript normalization without indexing or model imports."""

import logging
import os
import subprocess

from shyhurricane.command_image import unix_command_image

logger = logging.getLogger(__name__)


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
