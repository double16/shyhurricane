from __future__ import annotations

import json
import logging
import subprocess
from multiprocessing import Queue
from typing import Optional, List

import persistqueue
from mcp import Resource
from pydantic import AnyUrl

from shyhurricane.index.input_documents import KatanaDocument, IngestableRequestResponse
from shyhurricane.task_queue.types import SpiderQueueItem, SpiderResultItem
from shyhurricane.utils import BeautifulSoupExtractor, urlparse_ext, HttpResource, \
    extract_domain, unix_command_image

logger = logging.getLogger(__name__)


def spider_worker(
        item: SpiderQueueItem,
        ingest_queue: persistqueue.SQLiteAckQueue,
        spider_result_queue: Queue[SpiderResultItem]):
    _katana_ingest(
        item=item,
        ingest_queue=ingest_queue,
        result_queue=spider_result_queue,
    )


def _katana_ingest(
        item: SpiderQueueItem,
        ingest_queue: persistqueue.SQLiteAckQueue,
        result_queue: Queue[SpiderResultItem] = None,
) -> None:
    katana_command = ["katana", "-u", item.uri, "-js-crawl", "-jsluice", "-known-files", "all", "-field-scope", "fqdn",
                      "-form-extraction", "-tech-detect", "-ignore-query-params", "-strategy", "breadth-first",
                      "-jsonl", "-omit-raw", "-depth", str(item.depth), "-retry", "3", "-no-color",
                      "-silent"]

    if item.rate_limit_requests_per_second:
        katana_command.extend(["-rate-limit", str(item.rate_limit_requests_per_second)])
    if item.user_agent:
        katana_command.extend(["-H", f"User-Agent: {item.user_agent}"])
    if item.request_headers:
        for k, v in item.request_headers.items():
            katana_command.extend(["-H", f"{k}: {v}"])
    if item.cookies:
        cookie_data = "; ".join(map(lambda e: f"{e[0]}={e[1]}", item.cookies.items()))
        katana_command.extend(["-H", f"Cookie: {cookie_data}"])

    docker_command = ["docker", "run", "--rm"]
    for host, ip in (item.additional_hosts or {}).items():
        docker_command.extend(["--add-host", f"{host}:{ip}"])
    docker_command.extend(
        [unix_command_image(), "timeout", "--kill-after=1m", "30m"])
    docker_command.extend(katana_command)

    logger.info(f"Spidering with command {' '.join(docker_command)}")
    proc = subprocess.Popen(docker_command, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    katana_component = KatanaDocument()
    soup_extractor = BeautifulSoupExtractor()
    result_count = [0]

    def process_stdout(data: str):
        if not data or '"request"' not in data:
            return

        ingest_queue.put(data)
        if result_queue is not None:
            try:
                katana_results: List[IngestableRequestResponse] = katana_component.run(data).get("request_responses",
                                                           [])
                for parsed in katana_results:
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
                            result_queue.put_nowait(SpiderResultItem(item.context_id, http_resource))
                            result_count[0] += 1
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
            process_stdout(line_out)
        # read any buffered output
        while True:
            line_out = proc.stdout.readline()
            if not line_out:
                break
            process_stdout(line_out)
    except EOFError:
        pass

    return_code = proc.wait()
    if return_code in [0, 124, 125, 137]:
        logger.info("Spider for %s completed with (at least) %d results", item.uri, result_count[0])
    else:
        logger.error("Spider for %s returned exit code %d", item.uri, return_code)

    if result_queue:
        result_queue.put_nowait(SpiderResultItem(item.context_id, None))

    return None
