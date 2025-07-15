#!/usr/bin/env python3
import argparse
import json
import sys

from pipeline import build_ingest_pipeline
from utils import add_generator_args, GeneratorConfig

# ─── Argument Parser ───────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Stream documents into Chroma via stdin (Katana format).")
parser.add_argument("--db", "-d", default="127.0.0.1:8200", help="Chroma location host:port")
add_generator_args(parser)
args = parser.parse_args()
generator_config = GeneratorConfig.from_args(args)

# ─── Process stdin line-by-line ───────────────────────────────────────
pipeline = build_ingest_pipeline(db=args.db, generator_config=generator_config)

for line in sys.stdin:
    try:
        url = str(json.loads(line).get('request', {}).get('endpoint', '???'))
    except Exception:
        url = '???'

    try:
        pipeline.run({"input_router": {"text": line.strip()}})
        print(f"[✔] Indexed {url}", file=sys.stderr)

    except Exception as e:
        print(f"[✘] Error: {url}, {e}", file=sys.stderr)
        continue
