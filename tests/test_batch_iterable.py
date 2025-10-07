import pytest

from shyhurricane.utils import batch_iterable


@pytest.mark.parametrize(
    "data,batch_size,expected",
    [
        ([1, 2, 3, 4, 5, 6, 7], 3, [[1, 2, 3], [4, 5, 6], [7]]),
        ([1, 2, 3, 4, 5, 6, 7], 1, [[1], [2], [3], [4], [5], [6], [7]]),
        ([1, 2, 3, 4], 2, [[1, 2], [3, 4]]),
        ([1, 2], 5, [[1, 2]]),
        ([], 3, []),
    ],
)
def test_batch_iterable(data, batch_size, expected):
    result = list(batch_iterable(data, batch_size))
    assert result == expected
