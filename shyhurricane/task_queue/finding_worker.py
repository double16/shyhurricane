import datetime
import hashlib
import json
import logging
import time
from dataclasses import replace

import persistqueue
from haystack import Document
from haystack.document_stores.types import DuplicatePolicy

from shyhurricane.embedder_cache import EmbedderCache
from shyhurricane.finding_identity import finding_fingerprint, finding_save_lock
from shyhurricane.finding_search import finding_search_metadata
from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.index.web_resources_pipeline import (
    GenerateTitleAndDescription,
    build_embedders,
    build_splitters,
    build_stores,
)
from shyhurricane.target_info import parse_target_info
from shyhurricane.task_queue.types import SaveFindingQueueItem
from shyhurricane.utils import get_log_path, get_log_timestamp, get_state_path

logger = logging.getLogger(__name__)

# Change this when previously indexed data becomes obsolete
FINDING_VERSION = 2


class FindingContext:
    def __init__(
            self,
            db: str,
            generator_config: GeneratorConfig,
            embedder_cache: EmbedderCache,
            doc_type_queue: persistqueue.SQLiteAckQueue,
            log_timestamp: str | None = None,
    ):
        self.stores = build_stores(db, {"finding"})
        # Recovery must retain the original vector when completing a pending handoff.
        self.stores["finding"].return_embedding = True
        self.lock_path = get_state_path(db, "finding_state") / "save.lock"
        self.embedders = build_embedders(doc_types={"finding"}, embedder_cache=embedder_cache)
        self.splitters = build_splitters(self.embedders)
        self.doc_type_queue = doc_type_queue
        self.gen_title = GenerateTitleAndDescription(generator_config)
        self.finding_log_path = get_log_path(db, f"finding-{log_timestamp or get_log_timestamp()}.jsonl")

    def warm_up(self):
        for embedder in self.embedders.values():
            if hasattr(embedder, "warm_up"):
                embedder.warm_up()


def save_finding_worker(ctx: FindingContext, item: SaveFindingQueueItem):
    try:
        fingerprint = finding_fingerprint(item.target, item.markdown)
    except ValueError:
        logger.error(f"Finding has invalid target: {item.target}")
        return

    with finding_save_lock(ctx.lock_path):
        existing = ctx.stores["finding"].filter_documents(filters={
            "field": "meta.finding_fingerprint", "operator": "==", "value": fingerprint,
        })
        if existing:
            doc = existing[0]
            if doc.meta.get("finding_handoff_pending"):
                _handoff_finding(ctx, doc)
            else:
                logger.debug("Skipping duplicate finding %s", doc.id)
            return
        _save_new_finding(ctx, item, fingerprint)


def _handoff_finding(ctx: FindingContext, doc: Document):
    metadata = {key: value for key, value in doc.meta.items() if key != "finding_handoff_pending"}
    downstream = replace(doc, meta=metadata)
    ctx.doc_type_queue.put(downstream)
    completed = replace(doc, meta={**metadata, "finding_handoff_pending": False})
    ctx.stores["finding"].write_documents([completed], policy=DuplicatePolicy.OVERWRITE)


def _save_new_finding(ctx: FindingContext, item: SaveFindingQueueItem, fingerprint: str):
    timestamp_float = time.time()
    timestamp = datetime.datetime.fromtimestamp(timestamp_float).isoformat()

    target_info = parse_target_info(item.target)

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
        **finding_search_metadata(target_info.url or "", target_info.host),
        "url": target_info.url or "",
        "netloc": target_info.netloc or "",
        "host": target_info.host or "",
        "port": target_info.port or (
            {"https": 443, "http": 80}.get(item.target.split(":", 1)[0].lower(), 0) if target_info.url else 0
        ),
        "domain": target_info.domain or "",
        "timestamp": timestamp,
        "timestamp_float": timestamp_float,
        "content_type": "text/x-finding",
        "status_code": "201",
        "http_method": "POST",
        "title": item.title or "",
        "content_sha256": content_sha256,
        "finding_fingerprint": fingerprint,
        "finding_handoff_pending": True,
    }

    doc = Document(
        content=str(item.markdown),
        meta=meta,
        id=item.finding_id or fingerprint.split(":", 1)[1],
    )

    if not item.title:
        doc = ctx.gen_title.run(documents=[doc])["documents"][0]

    logger.debug("Splitting finding '%s'", item.title)
    split_docs = ctx.splitters["finding"].run(documents=[doc])["documents"]
    logger.debug("Embedding finding '%s'", item.title)
    embedded_docs = ctx.embedders["finding"].run(documents=[split_docs[0]])["documents"]
    doc = replace(doc, embedding=embedded_docs[0].embedding)
    logger.debug("Storing finding '%s' into collection finding", item.title)
    ctx.stores["finding"].write_documents([doc], policy=DuplicatePolicy.OVERWRITE)

    _handoff_finding(ctx, doc)
