"""Requeue retained blocked captures after their failed prerequisite has recovered."""

import re

from shyhurricane.graph.model import identity
from shyhurricane.graph.policy import ANALYZER_VERSION, library_analysis


def recover_dependents(connection, after="", limit=100):
    """Inspect an indexed bounded page, preserving failure status until real processing succeeds."""
    rows = connection.execute(
        "SELECT id,error FROM work WHERE status='failed' AND id>? ORDER BY id LIMIT ?",
        (after, limit),
    ).fetchall()
    scheduled = 0
    with connection:
        for capture, error in rows:
            match = re.fullmatch(r"Dependency ([0-9a-f]{64}) failed", error or "")
            if match is None:
                continue
            recovered = connection.execute(
                "SELECT 1 FROM work WHERE id=? AND status='complete'", (match[1],),
            ).fetchone()
            if not recovered:
                continue
            if connection.execute(
                "SELECT 1 FROM graph_epoch_inputs WHERE capture_id=? AND state IN ('waiting','active') LIMIT 1",
                (capture,),
            ).fetchone():
                continue
            policy = connection.execute(
                "SELECT mode FROM analysis_policies WHERE capture_id=?", (capture,),
            ).fetchone()
            mode = library_analysis(policy[0] if policy else None)
            token = identity("dependency-recovery", capture, match[1], ANALYZER_VERSION, mode)
            scheduled += connection.execute(
                "INSERT OR IGNORE INTO graph_epoch_inputs VALUES (?,?,?,NULL,'waiting',?)",
                (token, capture, mode, token),
            ).rowcount
    return rows[-1][0] if len(rows) == limit else "", scheduled
