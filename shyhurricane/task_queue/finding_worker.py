import datetime
import hashlib
import json
import logging
import time

from haystack import Document
from haystack.document_stores.types import DuplicatePolicy

import persistqueue

from shyhurricane.embedder_cache import EmbedderCache
from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.index.web_resources_pipeline import GenerateTitleAndDescription, build_stores, build_embedders, \
    build_splitters
from shyhurricane.target_info import parse_target_info
from shyhurricane.task_queue.types import SaveFindingQueueItem
from shyhurricane.utils import get_log_path

logger = logging.getLogger(__name__)

# Change this when previously indexed data becomes obsolete
FINDING_VERSION = 1


class FindingContext:
    def __init__(
            self,
            db: str,
            generator_config: GeneratorConfig,
            embedder_cache: EmbedderCache,
            doc_type_queue: persistqueue.SQLiteAckQueue
    ):
        self.stores = build_stores(db, {"finding"})
        self.embedders = build_embedders(doc_types={"finding"}, embedder_cache=embedder_cache)
        self.splitters = build_splitters(self.embedders)
        self.doc_type_queue = doc_type_queue
        self.gen_title = GenerateTitleAndDescription(generator_config)
        self.finding_log_path = get_log_path(db, "finding.jsonl")

    def warm_up(self):
        for embedder in self.embedders.values():
            embedder.warm_up()


def save_finding_worker(ctx: FindingContext, item: SaveFindingQueueItem):
    timestamp_float = time.time()
    timestamp = datetime.datetime.fromtimestamp(timestamp_float).isoformat()

    try:
        target_info = parse_target_info(item.target)
    except ValueError as e:
        logger.error(f"Finding has invalid target: {item.target}")
        return

    if ctx.finding_log_path is not None:
        try:
            with open(ctx.finding_log_path, "a") as finding_log:
                finding_log.write(json.dumps({"target": item.target, "title": item.title, "markdown": item.markdown}))
                finding_log.write("\n")
        except Exception as e:
            logger.error("Failed to write finding log at %s: %s", ctx.finding_log_path, e)
            ctx.finding_log_path = None

    content_sha256 = hashlib.sha256(item.markdown.encode("utf-8", errors="ignore")).hexdigest()

    meta = {
        "version": FINDING_VERSION,
        "url": target_info.url or "",
        "netloc": target_info.netloc or "",
        "host": target_info.host or "",
        "port": target_info.port or 0,
        "domain": target_info.domain or "",
        "timestamp": timestamp,
        "timestamp_float": timestamp_float,
        "content_type": "text/x-finding",
        "status_code": "201",
        "http_method": "POST",
        "title": item.title or "",
        "content_sha256": content_sha256,
    }

    doc = Document(
        content=item.markdown,
        meta=meta,
    )

    if not item.title:
        doc = ctx.gen_title.run(documents=[doc])["documents"][0]

    logger.debug("Splitting finding '%s'", item.title)
    split_docs = ctx.splitters["finding"].run(documents=[doc])["documents"]
    logger.info("Embedding finding '%s'", item.title)
    embedded_docs = ctx.embedders["finding"].run(documents=[split_docs[0]])["documents"]
    doc.embedding = embedded_docs[0].embedding
    logger.info("Storing finding '%s' into collection finding", item.title)
    ctx.stores["finding"].write_documents([doc], policy=DuplicatePolicy.OVERWRITE)

    ctx.doc_type_queue.put(doc)
