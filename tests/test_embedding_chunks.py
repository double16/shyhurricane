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
