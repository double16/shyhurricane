import datetime
import logging
import time

from haystack import Document
from haystack.components.embedders import SentenceTransformersDocumentEmbedder
from haystack.document_stores.types import DuplicatePolicy

from shyhurricane.doc_type_model_map import doc_type_to_model
from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.index.web_resources_pipeline import GenerateTitleAndDescription
from shyhurricane.retrieval_pipeline import create_chrome_document_store
from shyhurricane.target_info import parse_target_info
from shyhurricane.task_queue.types import SaveFindingQueueItem

logger = logging.getLogger(__name__)

# Change this when previously indexed data becomes obsolete
FINDING_VERSION = 1


class FindingContext:
    def __init__(self, db: str, generator_config: GeneratorConfig):
        self.finding_store = create_chrome_document_store(db=db, collection_name="finding")
        self.finding_embedder = SentenceTransformersDocumentEmbedder(
            model=doc_type_to_model.get("finding"),
            batch_size=1,
            progress_bar=False)
        self.gen_title = GenerateTitleAndDescription(generator_config)

    def warm_up(self):
        self.finding_embedder.warm_up()


def save_finding_worker(ctx: FindingContext, item: SaveFindingQueueItem):
    timestamp_float = time.time()
    timestamp = datetime.datetime.fromtimestamp(timestamp_float).isoformat()

    try:
        target_info = parse_target_info(item.target)
    except ValueError as e:
        logger.error(f"Finding has invalid target: {item.target}")
        return

    meta = {
        "version": FINDING_VERSION,
        "url": target_info.url or "",
        "netloc": target_info.netloc or "",
        "host": target_info.host or "",
        "port": target_info.port or 0,
        "domain": target_info.domain or "",
        "timestamp": timestamp,
        "timestamp_float": timestamp_float,
        "content_type": "text/plain",
        "status_code": "201",
        "http_method": "POST",
        "title": item.title or "",
    }

    doc = Document(
        content=item.markdown,
        meta=meta,
    )

    if not item.title:
        doc = ctx.gen_title.run(documents=[doc])["documents"][0]

    finding_docs = ctx.finding_embedder.run(documents=[doc])["documents"]
    ctx.finding_store.write_documents(finding_docs, policy=DuplicatePolicy.OVERWRITE)
