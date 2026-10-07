import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest


@pytest.mark.skipif(not hasattr(os, "setsid"), reason="POSIX process groups required")
@pytest.mark.parametrize("forced", [False, True])
def test_spawned_ingest_watcher_worker_and_resource_tracker_exit(tmp_path, forced):
    script = tmp_path / "shutdown_probe.py"
    script.write_text(textwrap.dedent("""
        import json
        import multiprocessing as mp
        import os
        import signal
        import sys
        import time
        from multiprocessing import resource_tracker
        from types import SimpleNamespace

        from persistqueue import SQLiteAckQueue
        from shyhurricane.index import web_resources
        from shyhurricane.task_queue.types import TaskPool

        def worker(db, config, health_state=None, log_timestamp=None, stop_event=None):
            connection, forced = config
            if forced:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            queue = SQLiteAckQueue(db, auto_commit=True)
            doc_queue = SQLiteAckQueue(db + "-documents", auto_commit=True)

            def run(data):
                connection.send((os.getpid(), os.getpgrp()))
                stop_event.wait()
                if forced:
                    while True:
                        time.sleep(1)
                time.sleep(0.05)
                return {"output": {"documents": []}}

            web_resources.get_ingest_queue = lambda db: queue
            web_resources.get_doc_type_queue = lambda db: doc_queue
            web_resources.get_log_path = lambda db, name: os.path.join(db, "index.jsonl")
            web_resources.build_ingest_pipeline = lambda **kwargs: SimpleNamespace(run=run)
            try:
                web_resources._ingest_worker(db, object(), stop_event=stop_event)
            finally:
                queue.close()
                doc_queue.close()
                connection.close()

        def watcher(db, config, stop_event):
            web_resources._ingest_worker = worker
            web_resources._ingest_watcher(db, config, stop_event=stop_event)

        if __name__ == "__main__":
            ctx = mp.get_context("spawn")
            mp.set_start_method("spawn")
            os.environ["SHYHURRICANE_MONITOR"] = "1"
            db, mode = sys.argv[1:]
            forced = mode == "forced"
            queue = SQLiteAckQueue(db, auto_commit=True)
            queue.put("current")
            queue.put("pending")
            queue.close()
            stop = ctx.Event()
            receiver, sender = ctx.Pipe(duplex=False)
            process = ctx.Process(target=watcher, args=(db, (sender, forced), stop))
            process._shyhurricane_monitor_process_group = True
            process.start()
            sender.close()
            pool = TaskPool([process])
            try:
                if not receiver.poll(45):
                    raise RuntimeError("worker did not start")
                worker_pid, worker_group = receiver.recv()
                assert worker_group == process.pid
                tracker_pid = resource_tracker._resource_tracker._pid
                watcher_pid = process.pid
                stop.set()
                pool.close(deadline=time.monotonic() + (0.1 if forced else 10))
                pool.close()
                queue = SQLiteAckQueue(db, auto_commit=True)
                try:
                    assert queue.acked_count() == (0 if forced else 1)
                    queue.resume_unack_tasks()
                    expected = ["current", "pending"] if forced else ["pending"]
                    assert [queue.get(block=False) for _ in expected] == expected
                finally:
                    queue.close()
                print(json.dumps([watcher_pid, worker_pid, tracker_pid]), flush=True)
            finally:
                stop.set()
                pool.close()
                receiver.close()
    """))
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    result = subprocess.run(
        [sys.executable, str(script), str(tmp_path / "queue"), "forced" if forced else "graceful"],
        env=env, capture_output=True, text=True, timeout=65, check=True,
    )
    pids = json.loads(result.stdout.strip().splitlines()[-1])
    deadline = time.monotonic() + 10
    remaining = pids
    while remaining and time.monotonic() < deadline:
        remaining = [pid for pid in remaining if _process_is_running(pid)]
        if remaining:
            time.sleep(0.05)
    assert remaining == [], f"Processes survived shutdown: {remaining}"
    assert "leaked semaphore" not in result.stderr


def _process_is_running(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True, check=False)
    # A dead orphan may briefly remain a zombie until the OS reaps it.
    return bool(result.stdout.strip()) and not result.stdout.strip().startswith("Z")
