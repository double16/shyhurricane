"""Tests for the shared per-file Python coverage check."""

import importlib.util
from pathlib import Path

import pytest


COVERAGE_CHECK_PATH = Path(__file__).parents[2] / ".github/scripts/check-python-coverage-floor.py"
SPEC = importlib.util.spec_from_file_location("python_coverage_floor", COVERAGE_CHECK_PATH)
coverage_floor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage_floor)


def _coverage_data(covered_lines: int = 8, covered_branches: int = 8) -> dict[str, object]:
    return {
        "meta": {"branch_coverage": True},
        "files": {
            "src/example.py": {
                "summary": {
                    "covered_lines": covered_lines,
                    "num_statements": 10,
                    "covered_branches": covered_branches,
                    "num_branches": 10,
                }
            }
        },
    }


def test_evaluate_coverage_accepts_files_at_the_floor() -> None:
    assert coverage_floor.evaluate_coverage(_coverage_data(), 80.0, 80.0) == []


@pytest.mark.parametrize(
    ("covered_lines", "covered_branches", "expected"),
    [
        (7, 8, "line 70.0%"),
        (8, 7, "branch 70.0%"),
    ],
)
def test_evaluate_coverage_reports_each_metric_below_the_floor(
    covered_lines: int, covered_branches: int, expected: str
) -> None:
    failures = coverage_floor.evaluate_coverage(_coverage_data(covered_lines, covered_branches), 80.0, 80.0)

    assert failures == [f"src/example.py: {expected}"]


def test_evaluate_coverage_rejects_reports_without_branch_data() -> None:
    data = _coverage_data()
    data["meta"] = {"branch_coverage": False}

    with pytest.raises(ValueError, match="does not contain branch coverage data"):
        coverage_floor.evaluate_coverage(data, 80.0, 80.0)


def test_evaluate_coverage_rejects_reports_without_measured_files() -> None:
    data = {"meta": {"branch_coverage": True}, "files": {}}

    with pytest.raises(ValueError, match="contains no measured Python files"):
        coverage_floor.evaluate_coverage(data, 80.0, 80.0)
