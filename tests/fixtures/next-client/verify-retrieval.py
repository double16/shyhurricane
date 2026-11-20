"""Exercise production chunk discovery and real loopback HTTP retrieval."""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.extract import extract
from shyhurricane.graph.ingest import CaptureGraphEvents
from shyhurricane.graph.model import capture_event
from shyhurricane.index import next_chunks
from shyhurricane.index.input_documents import IngestableRequestResponse, KatanaDocument
from shyhurricane.persistent_queue import get_ingest_queue

FIXTURE = Path(__file__).resolve().parent
ROOT = FIXTURE.parents[2]


def analyze(source, filename):
    result = subprocess.run(
        ["node", str(ROOT / "src/docker/unix_command/graph-analysis/analyze.cjs")],
        input=json.dumps({"source": source, "filename": filename}), text=True,
        capture_output=True, check=True, timeout=30,
    )
    return json.loads(result.stdout)


def exchange(response):
    return IngestableRequestResponse(
        url=str(response.url), method="GET", timestamp="2026-01-01T00:00:00Z",
        request_headers={}, request_body=None, response_code=response.status_code,
        response_headers=dict(response.headers), response_body=response.text,
        response_rtt=None, technologies=None, forms=None,
    )


def verify(origin, scratch):
    def storage_path(db, name):
        return scratch / name

    with (
        patch("shyhurricane.persistent_queue.persistent_queue_path", storage_path),
        patch("shyhurricane.graph.artifacts.persistent_queue_path", storage_path),
        patch.object(next_chunks, "run_javascript", analyze),
    ):
        artifacts = ArtifactStore("fixture")
        queue = get_ingest_queue("fixture")
        try:
            page = httpx.get(origin + "/items/example")
            page.raise_for_status()
            soup = BeautifulSoup(page.text, "html.parser")
            manifest_path = next(
                script["src"] for script in soup.find_all("script", src=True)
                if script["src"].endswith("/_buildManifest.js")
            )
            manifest = httpx.get(urljoin(origin + "/", manifest_path))
            manifest.raise_for_status()
            declaration = exchange(manifest)
            CaptureGraphEvents("fixture").run([declaration])
            queue.close()
            queue = get_ingest_queue("fixture")
            declared = queue.size
            assert declared > 0
            # Closed world performs no HTTP requests and creates no responses.
            pending = queue.get(block=False)
            assert next_chunks.fetch_task(pending, open_world=False, artifacts=artifacts) is None
            queue.nack(pending)
            fetched = 0
            analyzed = 0
            while queue.size:
                task = queue.get(block=False)
                payload = next_chunks.fetch_task(task, open_world=True, artifacts=artifacts)
                assert payload is not None
                response = KatanaDocument().run(payload)["request_responses"][0]
                assert response.response_code == 200
                assert response.capture_provenance["declaring_capture"] == capture_event(declaration)["id"]
                artifacts.register(capture_event(response))
                # Analyze the actual delivered body without requesting source maps.
                graph = extract(capture_event(response), javascript_runner=analyze)
                assert graph.analysis
                fetched += 1
                analyzed += bool(graph.nodes)
                queue.ack(task)
            assert fetched == analyzed == declared
            CaptureGraphEvents("fixture").run([declaration])
            queue.close()
            queue = get_ingest_queue("fixture")
            assert queue.size == 0
            app = exchange(httpx.get(origin + "/", follow_redirects=True))
            next_chunks.schedule(artifacts, queue, app)
            assert queue.size > 0
            bound = 0
            while queue.size:
                task = queue.get(block=False)
                payload = next_chunks.fetch_task(task, open_world=True, artifacts=artifacts)
                assert payload is not None
                response = KatanaDocument().run(payload)["request_responses"][0]
                graph = extract(capture_event(response), javascript_runner=analyze)
                bound += sum(bool(node.get("declaring_reference_ids")) for node in graph.nodes.values())
                queue.ack(task)
            assert bound > 0
            print(f"Retrieved and analyzed {fetched} manifest chunks; Flight retrieval passed", flush=True)
        finally:
            queue.close()
            artifacts.close()


def main():
    port = os.environ.get("FIXTURE_PORT", "3930")
    origin = "http://127.0.0.1:" + port
    with tempfile.TemporaryDirectory(prefix="next-retrieval-") as directory:
        for bundler in ("webpack", "turbopack"):
            for maps in ("0", "1", "prefix") if bundler == "webpack" else ("0", "1"):
                base_path = "/base" if maps == "prefix" else ""
                prefix = f"http://localhost:{port}{base_path}" if maps == "prefix" else ""
                environment = {
                    **os.environ, "NEXT_TELEMETRY_DISABLED": "1",
                    "FIXTURE_BROWSER_MAPS": "0" if maps == "prefix" else maps,
                    "FIXTURE_BASE_PATH": base_path, "FIXTURE_ASSET_PREFIX": prefix,
                }
                subprocess.run(
                    ["node", "node_modules/next/dist/bin/next", "build", "--" + bundler],
                    cwd=FIXTURE, env=environment, check=True, stdout=subprocess.DEVNULL,
                )
                server = subprocess.Popen(
                    ["node", "node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", port],
                    cwd=FIXTURE, env=environment, stdout=subprocess.DEVNULL,
                )
                try:
                    for _ in range(100):
                        try:
                            if httpx.get(origin + base_path + "/", follow_redirects=True).status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("Fixture server failed to start")
                    print(f"{bundler} maps={maps}", flush=True)
                    verify(origin + base_path, Path(directory) / f"{bundler}-{maps}")
                finally:
                    server.terminate()
                    server.wait(timeout=10)


if __name__ == "__main__":
    main()
