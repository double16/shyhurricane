import json
import logging
import os
import subprocess
import time
from multiprocessing import Queue, Process
from typing import Optional, Dict, Tuple

from mcp import Resource
from pydantic import AnyUrl

from ingest_queue import get_ingest_queue
from utils import urlparse_ext, HttpResource, extract_domain

logger = logging.getLogger(__name__)


class SpiderQueueItem:
    def __init__(self,
                 uri: str,
                 depth: int = 3,
                 user_agent: Optional[str] = None,
                 request_headers: Optional[Dict[str, str]] = None,
                 ):
        self.uri = uri
        self.depth = depth
        self.user_agent = user_agent
        self.request_headers = request_headers


def _spider_worker(spider_queue: Queue, ingest_queue: Queue, spider_result_queue: Queue):
    while True:
        item: SpiderQueueItem = spider_queue.get()
        if item is None:
            break  # Sentinel to stop
        _katana_ingest(
            ingest_queue=ingest_queue,
            uri=item.uri,
            depth=item.depth,
            user_agent=item.user_agent,
            request_headers=item.request_headers,
            result_queue=spider_result_queue,
        )


def start_spider_worker(db_path: str) -> Tuple[Queue, Queue, Process]:
    ingest_queue = get_ingest_queue(db_path)
    spider_queue = Queue()
    spider_result_queue = Queue()
    process = Process(target=_spider_worker, args=(spider_queue, ingest_queue, spider_result_queue))
    process.start()
    return spider_queue, spider_result_queue, process


def _katana_ingest(
        ingest_queue: Queue,
        uri: str,
        depth: int = 3,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        result_queue: Queue = None,
) -> None:
    katana_command = ["katana", "-u", uri, "-js-crawl", "-jsluice", "-known-files", "all", "-field-scope", "fqdn",
                      "-form-extraction", "-tech-detect", "-ignore-query-params", "-strategy", "breadth-first",
                      "-jsonl", "-rate-limit", "5", "-omit-raw", "-depth", str(depth), "-retry", "3", "-no-color",
                      "-silent"]
    if user_agent:
        katana_command.extend(["-H", f"User-Agent: {user_agent}"])
    if request_headers:
        for k, v in request_headers.items():
            katana_command.extend(["-H", f"{k}: {v}"])

    logger.info(f"Spidering with command {' '.join(katana_command)}")
    last_report = time.time()
    proc = subprocess.Popen(katana_command, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)

    def process_stdout(data: str):
        ingest_queue.put_nowait(data)
        if result_queue:
            try:
                parsed = json.loads(data)
                url = parsed.get("request", {}).get("endpoint", "")
                if url:
                    resource = Resource(
                        name=url,
                        uri=AnyUrl(url),
                        mimeType=parsed.get('response', {}).get('headers', {}).get('content_type', ''),
                        size=parsed.get('response', {}).get('headers', {}).get('content_length', None),
                    )
                    try:
                        url_parsed = urlparse_ext(resource.name)
                        http_resource = HttpResource(
                            score=None,
                            url=resource.name,
                            host=url_parsed.hostname,
                            port=url_parsed.port,
                            domain=extract_domain(url_parsed.hostname),
                            status_code=parsed.get('response', {}).get('status_code', 0),
                            method=parsed.get('request', {}).get('method', 'GET'),
                            resource=resource,
                        )
                        result_queue.put_nowait(http_resource)
                    except Exception:
                        pass
            except Exception:
                pass

    while proc.poll() is None:
        line_err = proc.stderr.readline()
        line_out = proc.stdout.readline()
        if line_out and '"request"' in line_out:
            process_stdout(line_out)

        if time.time() - last_report > 5:
            last_report = time.time()
            # TODO: report to user

        if not line_err and not line_out:
            time.sleep(0.2)
    while True:
        line_out = proc.stdout.readline()
        if line_out and '"request"' in line_out:
            process_stdout(line_out)
        else:
            break

    return_code = proc.wait()
    if return_code != 0:
        logger.error("Spider for %s returned exit code %d", uri, return_code)
    else:
        logger.info("Spider for %s completed", uri)

    if result_queue:
        result_queue.put_nowait(None)

    return None
