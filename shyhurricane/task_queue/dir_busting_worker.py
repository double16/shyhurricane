import logging
import subprocess
import time
import uuid
from multiprocessing import Queue
from typing import Optional, Dict, List

import persistqueue

from pipeline import KatanaDocument
from shyhurricane.task_queue.types import DirBustingQueueItem
from utils import IngestableRequestResponse

logger = logging.getLogger(__name__)


def dir_busting_worker(item: DirBustingQueueItem, ingest_queue: persistqueue.SQLiteQueue, result_queue: Queue):
    logger.info(f"Starting dir busting worker {item.uri}")
    _feroxbuster(
        ingest_queue=ingest_queue,
        result_queue=result_queue,
        uri=item.uri,
        depth=item.depth,
        wordlist=item.wordlist,
        extensions=item.extensions,
        ignored_response_codes=item.ignored_response_codes,
        user_agent=item.user_agent,
        request_headers=item.request_headers,
        additional_hosts=item.additional_hosts,
    )


def _feroxbuster(
        ingest_queue: persistqueue.SQLiteQueue,
        result_queue: Queue,
        uri: str,
        depth: int = 3,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        ignored_response_codes: Optional[List[int]] = None,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        additional_hosts: Dict[str, str] = None,
) -> None:
    # TODO: check for FUZZ in uri, user_agent or request_headers and run ffuf
    # TODO: should we enforce a hard timeout?

    feroxbuster_command = ["/usr/local/bin/feroxbuster", "-u", uri, "--depth", str(depth),
                           "--extract-links", "--threads", "5", "--scan-limit", "1", "--rate-limit", "5"]
    if wordlist:
        feroxbuster_command.extend(["--wordlist", wordlist])
    if ignored_response_codes:
        feroxbuster_command.extend(["--filter-status", ",".join(map(str, ignored_response_codes))])
    if extensions:
        feroxbuster_command.append("--extensions")
        feroxbuster_command.extend(extensions)
    # TODO: try to guess if we should include `--collection-extensions`

    if user_agent:
        feroxbuster_command.extend(["--user-agent", user_agent])
    if request_headers:
        for k, v in request_headers.items():
            feroxbuster_command.extend(["-H", f"{k}: {v}"])

    replay_codes = {200, 201, 400, 401, 402, 403, 500}  # TODO: use the default list from feroxbuster
    if ignored_response_codes:
        replay_codes.intersection_update(ignored_response_codes)
    feroxbuster_command.extend(
        ["--replay-proxy", "http://127.0.0.1:8080", "--replay-codes", ",".join(map(str, replay_codes)), "--insecure"])

    mitmdump_command = ["/usr/local/bin/mitmdump_virtualenv.sh", "-q", "-p", "8080", "-s",
                        "/usr/share/mitm_to_katana/mitm_to_katana.py"]
    if ignored_response_codes:
        mitmdump_command.extend(["--", "--ignore", ",".join(map(str, ignored_response_codes))])

    container_name = "dir_busting_" + uuid.uuid4().hex

    mitmdump_docker_command = ["docker", "run", "--rm", "--name", container_name]
    for host, ip in (additional_hosts or {}).items():
        mitmdump_docker_command.extend(["--add-host", f"{host}:{ip}"])
    mitmdump_docker_command.extend(["shyhurricane_unix_command:latest"])
    mitmdump_docker_command.extend(mitmdump_command)

    feroxbuster_docker_command = ["docker", "exec", container_name]
    feroxbuster_docker_command.extend(feroxbuster_command)

    logger.info(f"Dir busting with command {' '.join(feroxbuster_docker_command)}")
    mitmdump_proc = subprocess.Popen(mitmdump_docker_command, universal_newlines=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)
    while True:
        time.sleep(2)
        feroxbuster_proc = subprocess.Popen(feroxbuster_docker_command, universal_newlines=True,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if feroxbuster_proc.wait(2) != 125:  # 125 is returned when the named container isn't running
                break
        except subprocess.TimeoutExpired:
            # assume the process is good because it didn't exit immediately
            break

    katana_component = KatanaDocument()

    def process_stdout(data: str):
        ingest_queue.put_nowait(data)
        if result_queue is not None:
            try:
                katana_results: List[IngestableRequestResponse] = katana_component.run(data).get("request_responses",
                                                                                                 [])
                if not katana_results:
                    return
                parsed = katana_results[0]
                url = parsed.url
                result_queue.put_nowait(url)
            except Exception as e:
                logger.warning(f"Queueing dir busting results: {e}", exc_info=e)
                pass

    try:
        while feroxbuster_proc.poll() is None:
            line_out = mitmdump_proc.stdout.readline()
            if line_out and '"request"' in line_out:
                process_stdout(line_out)
        # read any buffered output
        while True:
            line_out = mitmdump_proc.stdout.readline()
            if not line_out:
                break
            if '"request"' in line_out:
                process_stdout(line_out)
    except EOFError:
        pass

    return_code = feroxbuster_proc.wait()
    mitmdump_proc.terminate()
    if return_code != 0:
        logger.error("Dir busting for %s returned exit code %d", uri, return_code)
    else:
        logger.info("Dir busting for %s completed", uri)

    if result_queue:
        result_queue.put_nowait(None)

    return None
