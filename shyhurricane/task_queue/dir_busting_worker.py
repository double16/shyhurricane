import json
import logging
import os
import subprocess
import time
import uuid
from multiprocessing import Queue
from typing import Optional, List, Set
from urllib.parse import urlencode

import persistqueue

from shyhurricane.index.input_documents import KatanaDocument, IngestableRequestResponse
from shyhurricane.task_queue.types import DirBustingQueueItem
from shyhurricane.utils import unix_command_image, remove_unencodable

logger = logging.getLogger(__name__)


def dir_busting_worker(item: DirBustingQueueItem, ingest_queue: persistqueue.SQLiteAckQueue, result_queue: Queue):
    logger.info(f"Starting dir busting worker {item.uri}")
    _do_busting(
        ingest_queue=ingest_queue,
        result_queue=result_queue,
        item=item,
    )


def _do_busting(
        ingest_queue: persistqueue.SQLiteAckQueue,
        result_queue: Queue,
        item: DirBustingQueueItem,
) -> None:
    # replay_codes = {200, 201, 302, 400, 401, 402, 403, 405, 500}
    replay_codes = set()  # default all codes
    if item.ignored_response_codes:
        replay_codes.intersection_update(item.ignored_response_codes)

    if ("FUZZ" in item.uri and not item.uri.endswith("/FUZZ")) or (item.user_agent and "FUZZ" in item.user_agent) or (
            item.request_headers and "FUZZ" in json.dumps(item.request_headers)):
        buster_command = _build_ffuf_command(
            item=item,
            replay_codes=replay_codes,
        )
    else:
        if item.uri.endswith("/FUZZ"):
            item.uri = item.uri[:-4]
        buster_command = _build_feroxbuster_command(
            item=item,
            replay_codes=replay_codes,
        )

    mitmdump_command = ["timeout", "--kill-after=1m", "35m",
                        "/usr/local/bin/mitmdump_virtualenv.sh", "-q", "-p", "8080", "-s",
                        "/usr/share/mitm_to_katana/mitm_to_katana.py"]
    # always ignore 404 Not Found
    mitmdump_command.extend(["--", "--ignore", ",".join(map(str, (item.ignored_response_codes or []) + [404]))])

    container_name = "dir_busting_" + uuid.uuid4().hex

    mitmdump_docker_command = ["docker", "run", "--rm", "--name", container_name]
    for host, ip in (item.additional_hosts or {}).items():
        mitmdump_docker_command.extend(["--add-host", f"{host}:{ip}"])
    if item.seclists_volume:
        mitmdump_docker_command.extend(["-v", f"{item.seclists_volume}:/usr/share/seclists"])
    if item.mcp_session_volume:
        mitmdump_docker_command.extend(["-v", f"{item.mcp_session_volume}:/work"])
    mitmdump_docker_command.append(unix_command_image())
    mitmdump_docker_command.extend(mitmdump_command)

    buster_docker_command = ["docker", "exec"]
    if item.work_path:
        buster_docker_command.extend(["--workdir", item.work_path])
    buster_docker_command.extend([container_name, "timeout", "--kill-after=1m", "30m"])
    buster_docker_command.extend(buster_command)

    logger.info(f"Dir busting with command {' '.join(buster_docker_command)}")
    mitmdump_proc = subprocess.Popen(mitmdump_docker_command, universal_newlines=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)
    try:
        mitmdump_return_code = mitmdump_proc.wait(timeout=2)
        logger.error("mitmdump for %s returned exit code %d", item.uri, mitmdump_return_code)
        return None
    except subprocess.TimeoutExpired:
        # this is good
        pass

    try:
        buster_proc_succeed = False
        for _ in range(5):
            time.sleep(2)
            buster_proc = subprocess.Popen(buster_docker_command, universal_newlines=True,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                if buster_proc.wait(2) != 125:  # 125 is returned when the named container isn't running
                    buster_proc_succeed = True
                    break
            except subprocess.TimeoutExpired:
                # assume the process is good because it didn't exit immediately
                buster_proc_succeed = True
                break
        if not buster_proc_succeed:
            logger.error("Dir busting for %s failed to start", item.uri)
            if result_queue:
                result_queue.put_nowait(None)
            return None

        logger.info("Dir busting for %s started", item.uri)

        katana_component = KatanaDocument()

        def process_stdout(data: str):
            if data.count("\n") > 1:
                logger.warning("Output from mitmdump has %d lines", data.count("\n"))
            else:
                logger.info("Processing line from mitmdump: %d bytes", len(data))
            data = remove_unencodable(data)
            try:
                json.loads(data)
            except json.decoder.JSONDecodeError:
                logger.warning("katana JSON is unparseable, possibly due to incorrect utf-8 encoding, skipping")
                return

            ingest_queue.put(data)
            if result_queue is not None:
                try:
                    katana_results: List[IngestableRequestResponse] = katana_component.run(data).get(
                        "request_responses", [])
                    if not katana_results:
                        return
                    parsed = katana_results[0]
                    url = parsed.url
                    logger.info("Sending URL to result_queue: %s", url)
                    result_queue.put_nowait(url)
                except Exception as e:
                    logger.warning(f"Queueing dir busting results: {e}", exc_info=e)
                    pass

        try:
            os.set_blocking(mitmdump_proc.stdout.fileno(), False)
            while buster_proc.poll() is None:
                line_out = mitmdump_proc.stdout.readline()
                if line_out:
                    if '"request"' in line_out:
                        process_stdout(line_out)
                else:
                    time.sleep(0.2)
            # read any buffered output
            while True:
                line_out = mitmdump_proc.stdout.readline()
                if not line_out:
                    break
                if '"request"' in line_out:
                    process_stdout(line_out)
        except EOFError:
            pass

        return_code = buster_proc.wait()

        if return_code in [0, 124, 125, 137]:
            logger.info("Dir busting for %s completed with exit code %d", item.uri, return_code)
            # logger.error("Dir busting errors %s", mitmdump_proc.stderr.read())
            # logger.error("Dir busting output %s", buster_proc.stdout.read())
            # logger.error("Dir busting errors %s", buster_proc.stderr.read())
        else:
            logger.error("Dir busting for %s returned exit code %d", item.uri, return_code)
            # logger.error("Dir busting errors %s", mitmdump_proc.stderr.read())
            # logger.error("Dir busting errors %s", buster_proc.stderr.read())
        return None
    finally:
        if result_queue:
            result_queue.put_nowait(None)
        subprocess.Popen(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)


def _build_feroxbuster_command(
        item: DirBustingQueueItem,
        replay_codes: Optional[Set[str]] = None,
) -> List[str]:
    command = ["/usr/local/bin/feroxbuster", "-u", item.uri, "--insecure", "--extract-links", "--threads", "5"]

    if item.rate_limit_requests_per_second:
        command.extend(["--scan-limit", "1", "--rate-limit", str(item.rate_limit_requests_per_second)])
    else:
        command.extend(["--auto-tune"])

    if item.depth > 1:
        command.extend(["--depth", str(item.depth)])
    else:
        command.extend(["--no-recursion"])

    if item.wordlist:
        command.extend(["--wordlist", item.wordlist])

    if item.ignored_response_codes:
        command.extend(["--filter-status", ",".join(map(str, item.ignored_response_codes))])

    if item.extensions:
        command.append("--extensions")
        command.extend(item.extensions)
    # TODO: try to guess if we should include `--collection-extensions`

    if item.user_agent:
        command.extend(["--user-agent", item.user_agent])

    if item.request_headers:
        for k, v in item.request_headers.items():
            command.extend(["-H", f"{k}: {v}"])

    if item.method:
        command.extend(["--methods", item.method])

    if item.cookies:
        for k, v in item.cookies.items():
            command.extend(["--cookies", f"{k}={v}"])

    if item.params:
        if item.method == "GET":
            for k, v in item.params.items():
                command.extend(["--query", f"{k}={v}"])
        else:
            post_data = urlencode(item.params, doseq=True)
            command.extend(["--data", post_data])

    command.extend(["--replay-proxy", "http://127.0.0.1:8080"])
    if replay_codes:
        command.extend(["--replay-codes", ",".join(map(str, replay_codes))])

    return command


def _build_ffuf_command(
        item: DirBustingQueueItem,
        replay_codes: Optional[Set[str]] = None,
) -> List[str]:
    command = ["/usr/bin/ffuf", "-u", item.uri, "-ac", "-s", "-sf"]

    if item.rate_limit_requests_per_second:
        command.extend(["-rate", str(item.rate_limit_requests_per_second)])

    if item.uri.endswith("FUZZ") and item.depth > 1:
        command.extend(["-recursion", "-recursion-depth", str(item.depth)])

    command.extend(["-w", item.wordlist or "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"])

    if item.ignored_response_codes:
        command.extend(["-fc", ",".join(map(str, item.ignored_response_codes))])

    if item.extensions:
        command.append("-e")
        command.append(",".join(item.extensions))

    if item.user_agent:
        command.extend(["-H", f"User-Agent: {item.user_agent}"])

    if item.request_headers:
        for k, v in item.request_headers.items():
            command.extend(["-H", f"{k}: {v}"])

    if item.method:
        command.extend(["-X", item.method])

    if item.cookies:
        cookie_data = "; ".join(map(lambda e: f"{e[0]}={e[1]}", item.cookies.items()))
        command.extend(["-b", cookie_data])

    if item.params:
        post_data = urlencode(item.params, doseq=True)
        command.extend(["-d", post_data])

    command.extend(["-replay-proxy", "http://127.0.0.1:8080"])

    return command
