import pytest
from haystack import Document

from shyhurricane import embedding_chunks as chunks


class Tokenizer:
    def encode(self, text, add_special_tokens=True):
        return list(text) + ([0, 0] if add_special_tokens else [])

    def num_special_tokens_to_add(self, pair=False):
        return 2

    def __call__(self, text, **kwargs):
        return {"offset_mapping": [(i, i + 1) for i in range(len(text))]}


@pytest.mark.parametrize("text", ["", "abc", "x" * 2046, "a" * 4096, "你好🙂" * 1000])
def test_chunks_fit_and_cover(monkeypatch, text):
    monkeypatch.setattr(chunks, "load_tokenizer", lambda name: Tokenizer())
    splitter = chunks.TokenSplitter("test")
    splitter.warm_up()
    result = splitter.run([Document(content=text, id="parent", meta={"type": "html"})])["documents"]
    covered = set()
    for i, doc in enumerate(result):
        assert len(Tokenizer().encode(doc.content)) <= 2048
        start = doc.meta["split_idx_start"]
        assert text[start:start + len(doc.content)] == doc.content
        covered.update(range(start, start + len(doc.content)))
        assert doc.id == f"parent_{i}"
    assert covered == set(range(len(text)))
    assert chunks.preview(text, "test") == result[0].content


def test_errors(monkeypatch):
    monkeypatch.setattr(chunks, "load_tokenizer", lambda name: Tokenizer())
    splitter = chunks.TokenSplitter("test", 2)
    splitter.warm_up()
    with pytest.raises(ValueError):
        splitter.run([Document(content="x")])
    with pytest.raises(ValueError):
        splitter.run([Document()])


def test_recounts_chunks_when_sliced_text_uses_more_tokens(monkeypatch):
    class ExpandingTokenizer(Tokenizer):
        def encode(self, text, add_special_tokens=True):
            return list(text) * 2 + ([0, 0] if add_special_tokens else [])

    monkeypatch.setattr(chunks, "load_tokenizer", lambda name: ExpandingTokenizer())
    splitter = chunks.TokenSplitter("test", 6)
    splitter.warm_up()

    result = splitter.run([Document(content="abcde", id="parent")])["documents"]

    assert [doc.content for doc in result] == ["ab", "c", "de"]
    assert [doc.meta["split_idx_start"] for doc in result] == [0, 2, 3]
    assert all(len(splitter.tokenizer.encode(doc.content)) <= 6 for doc in result)


def test_rejects_character_that_exceeds_available_tokens(monkeypatch):
    class ExpandingTokenizer(Tokenizer):
        def encode(self, text, add_special_tokens=True):
            return list(text) * 2 + ([0, 0] if add_special_tokens else [])

    monkeypatch.setattr(chunks, "load_tokenizer", lambda name: ExpandingTokenizer())
    splitter = chunks.TokenSplitter("test", 3)
    splitter.warm_up()

    with pytest.raises(ValueError, match="Cannot fit a character"):
        splitter.run([Document(content="x")])


@pytest.mark.parametrize("text", ["x" * 100000, "你好🙂 " * 25000, " " * 100000])
def test_large_inputs_have_bounded_linear_work(monkeypatch, text):
    class RecordingTokenizer(Tokenizer):
        def __init__(self):
            self.sizes = []

        def __call__(self, text, **kwargs):
            self.sizes.append(len(text))
            return super().__call__(text, **kwargs)

    tokenizer = RecordingTokenizer()
    monkeypatch.setattr(chunks, "load_tokenizer", lambda name: tokenizer)
    first = chunks.preview(text, "test")
    assert tokenizer.sizes == [chunks.CHAR_WINDOW]
    tokenizer.sizes.clear()
    splitter = chunks.TokenSplitter("test")
    splitter.warm_up()
    parts = splitter.run([Document(content=text)])["documents"]
    assert first == parts[0].content
    assert max(tokenizer.sizes) <= chunks.CHAR_WINDOW
    assert sum(tokenizer.sizes) < len(text) * 6
    covered_until = 0
    for part in parts:
        start = part.meta["split_idx_start"]
        assert start <= covered_until
        assert part.content == text[start:start + len(part.content)]
        assert len(tokenizer.encode(part.content)) <= chunks.TOKEN_LIMIT
        covered_until = start + len(part.content)
    assert covered_until == len(text)
