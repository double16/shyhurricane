"""Durable graph capture before vector-store normalization and deduplication."""

from haystack import component

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.model import capture_event
from shyhurricane.index.input_documents import IngestableRequestResponse
from shyhurricane.persistent_queue import get_persistent_queue


class GraphCaptureError(RuntimeError):
    """Durable graph handoff failed; retain the original ingest item for retry."""


@component
class CaptureGraphEvents:
    def __init__(self, db: str):
        self.db = db

    @component.output_types(request_responses=list[IngestableRequestResponse])
    def run(self, request_responses: list[IngestableRequestResponse]):
        artifacts = None
        queue = None
        try:
            artifacts = ArtifactStore(self.db)
            queue = get_persistent_queue(self.db, "graph_queue", auto_resume=False)
            for request_response in request_responses:
                event = capture_event(request_response)
                event = artifacts.register(event)
                queue.put(event)
        except Exception as error:
            raise GraphCaptureError("Cannot durably queue graph capture") from error
        finally:
            if artifacts is not None:
                artifacts.close()
            if queue is not None:
                queue.close()
        return {"request_responses": request_responses}
