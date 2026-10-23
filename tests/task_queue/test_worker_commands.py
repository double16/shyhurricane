import pytest

from shyhurricane.task_queue import DirBustingQueueItem
from shyhurricane.task_queue.dir_busting_worker import _build_feroxbuster_command, _build_ffuf_command


@pytest.mark.parametrize("rate", [None, 0, 1, 5])
@pytest.mark.parametrize("builder,flag", [
    (_build_feroxbuster_command, "--rate-limit"), (_build_ffuf_command, "-rate"),
])
def test_buster_rate_limit_arguments(builder, flag, rate):
    item = DirBustingQueueItem("ctx", "http://target.local/FUZZ", rate_limit_requests_per_second=rate)
    command = builder(item)
    if rate is None:
        assert flag not in command
    else:
        assert command[command.index(flag) + 1] == str(rate)
    if builder is _build_feroxbuster_command:
        assert ("--auto-tune" in command) is (rate is None)
        assert ("--scan-limit" in command) is (rate is not None and rate > 0)
        if rate is not None and rate > 0:
            assert command[command.index("--scan-limit") + 1] == "1"


def test_build_feroxbuster_command_includes_options_for_get_request():
    item = DirBustingQueueItem(
        "ctx",
        "https://example.com/",
        depth=2,
        wordlist="/tmp/words.txt",
        extensions=["php", "txt"],
        ignored_response_codes=[404, 500],
        user_agent="agent",
        request_headers={"X-Test": "yes"},
        cookies={"sid": "abc"},
        params={"debug": "1"},
        rate_limit_requests_per_second=5,
    )

    command = _build_feroxbuster_command(item, replay_codes={200, 302})

    assert command[:4] == ["feroxbuster", "-u", "https://example.com/", "--insecure"]
    assert "--scan-limit" in command
    assert "--rate-limit" in command
    assert "5" in command
    assert "--depth" in command
    assert "--wordlist" in command
    assert "--extensions" in command
    assert "-H" in command
    assert "--cookies" in command
    assert "--query" in command
    assert "--replay-codes" in command


def test_build_feroxbuster_command_for_post_no_recursion_random_agent():
    item = DirBustingQueueItem(
        "ctx",
        "https://example.com/",
        depth=1,
        method="POST",
        params={"a": "b"},
    )

    command = _build_feroxbuster_command(item)

    assert "--auto-tune" in command
    assert "--no-recursion" in command
    assert "--random-agent" in command
    assert "--data" in command
    assert "a=b" in command


def test_build_ffuf_command_includes_fuzz_options():
    item = DirBustingQueueItem(
        "ctx",
        "https://example.com/FUZZ",
        depth=3,
        wordlist="/tmp/words.txt",
        extensions=["php"],
        ignored_response_codes=[404],
        user_agent="agent",
        request_headers={"X-Test": "yes"},
        cookies={"sid": "abc"},
        params={"a": "b"},
        rate_limit_requests_per_second=10,
    )

    command = _build_ffuf_command(item, replay_codes={200})

    assert command[:5] == ["ffuf", "-u", "https://example.com/FUZZ", "-ac", "-s"]
    assert "-rate" in command
    assert "-recursion" in command
    assert "-w" in command
    assert "-fc" in command
    assert "-e" in command
    assert "-b" in command
    assert "-d" in command
    assert "-replay-proxy" in command


def test_build_ffuf_command_uses_defaults_without_optional_filters():
    item = DirBustingQueueItem("ctx", "https://example.com/path/FUZZ", depth=1)

    command = _build_ffuf_command(item)

    assert command[:3] == ["ffuf", "-u", "https://example.com/path/FUZZ"]
    assert "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt" in command
    assert "-recursion" not in command
    assert "-fc" not in command
    assert "-e" not in command
