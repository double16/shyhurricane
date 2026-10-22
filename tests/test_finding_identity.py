"""Finding identity boundaries and process-safe save serialization."""

import multiprocessing

import pytest

from shyhurricane.finding_identity import finding_fingerprint, finding_save_lock, normalized_target


@pytest.mark.parametrize("first,second", [
    ("https://EXAMPLE.com:443", "https://example.com/"),
    ("HTTP://EXAMPLE.com:80/a", "http://example.com/a"),
    ("EXAMPLE.com:8080", "example.com:8080"),
    ("EXAMPLE.com", "example.com"),
    ("[2001:DB8::1]:8080", "[2001:db8::1]:8080"),
    ("https://[2001:DB8::1]:443", "https://[2001:db8::1]/"),
])
def test_equivalent_target_spellings(first, second):
    assert normalized_target(first) == normalized_target(second)
    assert finding_fingerprint(first, " \r\n# finding\r\n") == finding_fingerprint(second, "# finding")


@pytest.mark.parametrize("target", [
    "http://example.com/", "https://example.com:8443/", "example.com", "example.com:443",
    "https://other.example.com/", "https://example.com/Path", "https://example.com/?a=1",
    "https://example.com/#part", "https://example.com/?", "https://example.com/#",
    "https://user:pass@example.com/",
])
def test_distinct_target_scopes(target):
    assert finding_fingerprint(target, "body") != finding_fingerprint("https://example.com/", "body")


@pytest.mark.parametrize("first,second", [
    ("# finding\nnew evidence", "# finding\nold evidence"),
    ("code\n    indented", "code\nindented"),
    ("finding", "Finding"),
    ("é", "e"),
])
def test_substantive_content_is_distinct(first, second):
    assert finding_fingerprint("example.com", first) != finding_fingerprint("example.com", second)


def test_normalization_preserves_url_details():
    assert normalized_target("https://User:Secret@EXAMPLE.com:8443/Path?b=2&a=1#Part") == (
        "https://User:Secret@example.com:8443/Path?b=2&a=1#Part"
    )
    assert normalized_target("https://example.com/?#part") == "https://example.com/?#part"
    assert normalized_target("https://example.com/?#") == "https://example.com/?#"
    assert finding_fingerprint("example.com", "a\rb") == finding_fingerprint("example.com", "a\nb")


def test_invalid_target():
    with pytest.raises(ValueError):
        finding_fingerprint("not a target", "body")


def _acquire_lock(path, started, acquired):
    started.set()
    with finding_save_lock(path):
        acquired.set()


def test_lock_serializes_processes_and_releases_after_failure(tmp_path):
    process_context = multiprocessing.get_context("spawn")
    started = process_context.Event()
    acquired = process_context.Event()
    path = tmp_path / "save.lock"
    process = process_context.Process(target=_acquire_lock, args=(path, started, acquired))
    try:
        with pytest.raises(RuntimeError, match="interrupted"):
            with finding_save_lock(path):
                process.start()
                assert started.wait(15)
                assert not acquired.wait(0.1)
                raise RuntimeError("interrupted")
        assert acquired.wait(15)
        process.join(15)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(15)
