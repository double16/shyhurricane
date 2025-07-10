#!/usr/bin/env python3
import argparse
import sys

from pipeline import build_ingest_pipeline

# ─── Argument Parser ───────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Stream documents into Chroma via stdin (Katana format).")
parser.add_argument("--db", "-d", default="chroma_store", help="Chroma document store directory or host:port")
args = parser.parse_args()
persist_dir = args.db

# ─── Process stdin line-by-line ───────────────────────────────────────
pipeline = build_ingest_pipeline(db=args.db)

for line in sys.stdin:
    try:
        pipeline.run({"input_router": {"text": line.strip()}})

        print(f"[✔] Indexed", file=sys.stderr)

    except Exception as e:
        print(f"[✘] Error: {e}", file=sys.stderr)
        continue
