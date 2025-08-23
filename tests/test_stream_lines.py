import asyncio
import unittest
from typing import AsyncGenerator, List

from shyhurricane.utils import stream_lines


async def mock_bytes_stream(text: str):
    data = text.encode(encoding="utf-8")
    chunk_size = 32
    offset = 0
    while offset < len(data):
        yield data[offset:offset + chunk_size]
        offset += chunk_size


async def collect_lines(gen: AsyncGenerator) -> List[str]:
    result = []
    async for line in gen:
        result.append(line)
    return result


class TestStreamLines(unittest.TestCase):
    def test_stream_lines_one(self):
        lines = asyncio.run(collect_lines(stream_lines(mock_bytes_stream("abc"))))
        self.assertEqual(["abc"], lines)

    def test_stream_lines_two(self):
        lines = asyncio.run(collect_lines(stream_lines(mock_bytes_stream("a\nb\n"))))
        self.assertEqual(["a", "b"], lines)
        l1 = "a" * 64
        l2 = "b" * 64
        lines = asyncio.run(collect_lines(stream_lines(mock_bytes_stream(f"{l1}\n{l2}"))))
        self.assertEqual([l1, l2], lines)
        lines = asyncio.run(collect_lines(stream_lines(mock_bytes_stream(f"{l1}\n{l2}\n"))))
        self.assertEqual([l1, l2], lines)
