import json
import logging
import subprocess
import time
import uuid
from multiprocessing import Queue
from typing import Optional, Dict, List, Set

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
    # TODO: should we enforce a hard timeout?

    # replay_codes = {200, 201, 302, 400, 401, 402, 403, 405, 500}
    replay_codes = set()  # default all codes
    if ignored_response_codes:
        replay_codes.intersection_update(ignored_response_codes)

    if "FUZZ" in uri or (user_agent and "FUZZ" in user_agent) or (
            request_headers and "FUZZ" in json.dumps(request_headers)):
        buster_command = _build_ffuf_command(
            depth=depth,
            ignored_response_codes=ignored_response_codes,
            request_headers=request_headers,
            replay_codes=replay_codes,
            uri=uri,
            user_agent=user_agent,
            wordlist=wordlist,
        )
    else:
        buster_command = _build_feroxbuster_command(
            depth=depth,
            extensions=extensions,
            ignored_response_codes=ignored_response_codes,
            request_headers=request_headers,
            replay_codes=replay_codes,
            uri=uri,
            user_agent=user_agent,
            wordlist=wordlist,
        )

    mitmdump_command = ["/usr/local/bin/mitmdump_virtualenv.sh", "-q", "-p", "8080", "-s",
                        "/usr/share/mitm_to_katana/mitm_to_katana.py"]
    # always ignore 404 Not Found and 301 Redirect, very common for URLs that do not exist
    mitmdump_command.extend(["--", "--ignore", ",".join(map(str, (ignored_response_codes or []) + [404, 301]))])

    container_name = "dir_busting_" + uuid.uuid4().hex

    mitmdump_docker_command = ["docker", "run", "--rm", "--name", container_name]
    for host, ip in (additional_hosts or {}).items():
        mitmdump_docker_command.extend(["--add-host", f"{host}:{ip}"])
    mitmdump_docker_command.extend(["shyhurricane_unix_command:latest"])
    mitmdump_docker_command.extend(mitmdump_command)

    feroxbuster_docker_command = ["docker", "exec", container_name]
    feroxbuster_docker_command.extend(buster_command)

    logger.info(f"Dir busting with command {' '.join(feroxbuster_docker_command)}")
    mitmdump_proc = subprocess.Popen(mitmdump_docker_command, universal_newlines=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)

    buster_proc_succeed = False
    for _ in range(5):
        time.sleep(2)
        buster_proc = subprocess.Popen(feroxbuster_docker_command, universal_newlines=True,
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
        logger.error("Dir busting failed to start")
        if result_queue:
            result_queue.put_nowait(None)
        return None

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
        while buster_proc.poll() is None:
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

    return_code = buster_proc.wait()
    mitmdump_proc.terminate()
    if return_code != 0:
        logger.error("Dir busting for %s returned exit code %d", uri, return_code)
    else:
        logger.info("Dir busting for %s completed", uri)

    if result_queue:
        result_queue.put_nowait(None)

    return None


def _build_feroxbuster_command(
        uri: str,
        depth: int,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        ignored_response_codes: Optional[List[int]] = None,
        replay_codes: Optional[Set[str]] = None,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
) -> List[str]:
    feroxbuster_command = ["/usr/local/bin/feroxbuster", "-u", uri,
                           "--extract-links", "--threads", "5", "--scan-limit", "1", "--rate-limit", "5"]
    if depth > 1:
        feroxbuster_command.extend(["--depth", str(depth)])
    else:
        feroxbuster_command.extend(["--no-recursion"])
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
    feroxbuster_command.extend(["--replay-proxy", "http://127.0.0.1:8080", "--insecure"])
    if replay_codes:
        feroxbuster_command.extend(["--replay-codes", ",".join(map(str, replay_codes))])
    return feroxbuster_command


def _build_ffuf_command(
        uri: str,
        depth: int,
        wordlist: Optional[str] = None,
        ignored_response_codes: Optional[List[int]] = None,
        replay_codes: Optional[Set[str]] = None,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
) -> List[str]:
    command = ["/usr/bin/ffuf", "-u", uri, "-ac", "-s", "-sf", "-rate", "5"]
    if uri.endswith("FUZZ") and depth > 1:
        command.extend(["-recursion", "-recursion-depth", str(depth)])
    command.extend(["-w", wordlist or "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"])
    if ignored_response_codes:
        command.extend(["-fc", ",".join(map(str, ignored_response_codes))])
    if user_agent:
        command.extend(["-H", f"User-Agent: {user_agent}"])
    if request_headers:
        for k, v in request_headers.items():
            command.extend(["-H", f"{k}: {v}"])
    command.extend(["-replay-proxy", "http://127.0.0.1:8080"])
    return command
