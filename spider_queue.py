import json
import logging
import subprocess
from multiprocessing import Queue, Process
from typing import Optional, Dict, Tuple, List

import persistqueue
from mcp import Resource
from pydantic import AnyUrl

from ingest_queue import get_ingest_queue
from pipeline import KatanaDocument
from utils import urlparse_ext, HttpResource, extract_domain, IngestableRequestResponse, BeautifulSoupExtractor

logger = logging.getLogger(__name__)


class SpiderQueueItem:
    def __init__(self,
                 uri: str,
                 depth: int = 3,
                 user_agent: Optional[str] = None,
                 request_headers: Optional[Dict[str, str]] = None,
                 additional_hosts: Dict[str, str] = None,
                 ):
        self.uri = uri
        self.depth = depth
        self.user_agent = user_agent
        self.request_headers = request_headers
        self.additional_hosts = additional_hosts


def _spider_worker(spider_queue: Queue, ingest_queue_path: str, spider_result_queue: Queue):
    ingest_queue = persistqueue.SQLiteQueue(path=ingest_queue_path, auto_commit=True)
    while True:
        item: SpiderQueueItem = spider_queue.get()
        if item is None:
            logger.info("Exiting the spider queue")
            break  # Sentinel to stop
        _katana_ingest(
            ingest_queue=ingest_queue,
            uri=item.uri,
            depth=item.depth,
            user_agent=item.user_agent,
            request_headers=item.request_headers,
            result_queue=spider_result_queue,
            additional_hosts=item.additional_hosts,
        )


def start_spider_worker(db: str) -> Tuple[Queue, Queue, Process]:
    ingest_queue = get_ingest_queue(db)
    spider_queue = Queue()
    spider_result_queue = Queue()
    process = Process(target=_spider_worker, args=(spider_queue, ingest_queue.path, spider_result_queue))
    process.start()
    return spider_queue, spider_result_queue, process


def _katana_ingest(
        ingest_queue: persistqueue.SQLiteQueue,
        uri: str,
        depth: int = 3,
        user_agent: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        result_queue: Queue = None,
        additional_hosts: Dict[str, str] = None,
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

    docker_command = ["docker", "run", "--rm"]
    for host, ip in (additional_hosts or {}).items():
        docker_command.extend(["--add-host", f"{host}:{ip}"])
    docker_command.extend(["shyhurricane_unix_command:latest"])
    docker_command.extend(katana_command)

    logger.info(f"Spidering with command {' '.join(docker_command)}")
    proc = subprocess.Popen(docker_command, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    katana_component = KatanaDocument()
    soup_extractor = BeautifulSoupExtractor()

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
                status_code = parsed.response_code
                if url and status_code > 0:
                    raw_mime = parsed.response_headers.get("Content-Type", "").lower().split(";")[0].strip()
                    title: Optional[str] = None
                    description: Optional[str] = None
                    if parsed.response_body and raw_mime == "text/html":
                        title, description = soup_extractor.extract(parsed.response_body)

                    resource = Resource(
                        name=url,
                        uri=AnyUrl(url),
                        title=title,
                        description=description,
                        mimeType=parsed.response_headers.get('Content-Type', ''),
                        size=parsed.response_headers.get('Content-Length', None),
                    )
                    try:
                        url_parsed = urlparse_ext(resource.name)
                        http_resource = HttpResource(
                            score=100,
                            url=resource.name,
                            host=url_parsed.hostname,
                            port=url_parsed.port,
                            domain=extract_domain(url_parsed.hostname),
                            status_code=status_code,
                            method=parsed.method,
                            response_headers=parsed.response_headers,
                            resource=resource,
                            contents=None,
                        )
                        result_queue.put_nowait(http_resource)
                    except Exception as e:
                        logger.warning(f"Queueing spider results: {e}", exc_info=e)
                        pass
            except json.decoder.JSONDecodeError as e:
                logger.warning(f"Parsing katana output: {e}\n\n{data}", exc_info=e)
            except Exception as e:
                logger.warning(f"Queueing spider results: {e}", exc_info=e)
                pass

    try:
        while proc.poll() is None:
            line_out = proc.stdout.readline()
            if line_out and '"request"' in line_out:
                process_stdout(line_out)
        # read any buffered output
        while True:
            line_out = proc.stdout.readline()
            if not line_out:
                break
            if '"request"' in line_out:
                process_stdout(line_out)
    except EOFError:
        pass

    return_code = proc.wait()
    if return_code != 0:
        logger.error("Spider for %s returned exit code %d", uri, return_code)
    else:
        logger.info("Spider for %s completed", uri)

    if result_queue:
        result_queue.put_nowait(None)

    return None
