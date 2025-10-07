import pytest

from shyhurricane.utils import validate_container_file_path


@pytest.mark.parametrize("path,expect_exception", [
    # Disallow traversal
    ("../etc/passwd", True),
    ("/safe/../file", True),
    ("..", True),
    ("../", True),

    # Relative paths (allowed)
    ("etc/passwd", False),
    ("file.txt", False),
    ("subdir/another.txt", False),
    ("", True),

    # Allowed absolute paths
    ("/tmp/test.txt", False),
    ("/var/tmp/something", False),

    # Disallowed absolute paths
    ("/etc/passwd", True),
    ("/home/user/file", True),
    ("/opt/data", True),
])
def test_validate_container_file_path(path, expect_exception):
    if expect_exception:
        with pytest.raises(ValueError):
            validate_container_file_path(path)
    else:
        validate_container_file_path(path)
