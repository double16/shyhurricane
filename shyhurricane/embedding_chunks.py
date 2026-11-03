"""Token-bounded embedding inputs, independent of provider request batching."""

from functools import lru_cache

from haystack import Document

TOKEN_LIMIT = 2048
TOKENIZERS = {
    "nomic-embed-text": "nomic-ai/nomic-embed-text-v1.5",
    "jina-embeddings-v2-base-code": "jinaai/jina-embeddings-v2-base-code",
}


@lru_cache(maxsize=8)
def load_tokenizer(model_name):
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(TOKENIZERS.get(model_name, model_name), use_fast=True)


class TokenSplitter:
    """Slice original text at tokenizer offsets and validate complete inputs."""

    def __init__(self, model_name, limit=TOKEN_LIMIT):
        self.model_name = model_name
        self.limit = min(limit, TOKEN_LIMIT)

    def warm_up(self):
        self.tokenizer = load_tokenizer(self.model_name)

    def _count(self, text):
        return len(self.tokenizer.encode(text, add_special_tokens=True))

    def run(self, documents):
        parts = []
        for doc in documents:
            if doc.content is None:
                raise ValueError("Document content is required")
            text = doc.content
            start = 0
            index = 0
            while start < len(text) or index == 0:
                offsets = self.tokenizer(text[start:], add_special_tokens=False, return_offsets_mapping=True)[
                    "offset_mapping"
                ]
                budget = self.limit - self.tokenizer.num_special_tokens_to_add(pair=False)
                if budget < 1:
                    raise ValueError("Token limit cannot accommodate special tokens")
                end = len(text) if len(offsets) <= budget else start + offsets[budget][0]
                while end > start and self._count(text[start:end]) > self.limit:
                    end -= 1
                if end <= start and text:
                    raise ValueError("Cannot fit a character within embedding token limit")
                meta = dict(doc.meta)
                meta.update(source_id=doc.id, split_id=index, split_idx_start=start)
                parts.append(Document(content=text[start:end], id=f"{doc.id}_{index}", meta=meta))
                if end == len(text):
                    break
                overlap = int(self.limit * 0.06)
                consumed = [a for a, b in offsets if b <= end - start]
                next_start = start + consumed[-overlap] if overlap and len(consumed) > overlap else end
                start = max(start + 1, next_start)
                index += 1
        return {"documents": parts}


def preview(text, model_name):
    splitter = TokenSplitter(model_name)
    splitter.warm_up()
    return splitter.run([Document(content=text)])["documents"][0].content
