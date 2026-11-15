"""Runs in ace3's dev container: ace3's search code and its embedding model over cases.json.

    /venv/bin/python3 reference.py <cases.json> <model directory> <out.json>

For each text: its sparse terms (`lexical_tokens`), their ids and weights (`term_weights`), the
model's token bounds (`token_offsets`, as bytes of the UTF-8 text), its chunks under each case's
sizes (`chunk_text`), and the model's embedding of it (`encode_documents`). ace3's configuration,
database and Qdrant aren't loaded or touched: the model is read from the directory given, which
ace3's indexer downloaded, and nothing is written but the output file.
"""

import json
import sys

sys.path.insert(0, "/opt/ace")

from sentence_transformers import SentenceTransformer  # noqa: E402

from saq.search.chunking import chunk_text, token_offsets  # noqa: E402
from saq.search.sparse import identifiers, lexical_tokens, term_weights  # noqa: E402


def byte_offsets(text, offsets):
    """Character bounds as bounds in the text's UTF-8 bytes."""
    prefix = [0]
    for char in text:
        prefix.append(prefix[-1] + len(char.encode("utf-8")))
    return [[prefix[start], prefix[end]] for start, end in offsets]


def main():
    cases_path, model_dir, out_path = sys.argv[1:4]
    with open(cases_path) as fp:
        cases = json.load(fp)

    model = SentenceTransformer(model_dir, device="cpu")
    out = {"model": {"dimension": int(model.get_embedding_dimension()), "max_seq_length": int(model.max_seq_length)}, "texts": [], "chunks": []}

    texts = cases["texts"]
    vectors = model.encode(texts, batch_size=32, normalize_embeddings=True, show_progress_bar=False)
    for text, vector in zip(texts, vectors):
        stripped = text.strip()
        out["texts"].append({
            "text": text,
            "identifiers": identifiers(text),
            "tokens": lexical_tokens(text),
            "weights": sorted([index, weight] for index, weight in term_weights(text).items()),
            "offsets": byte_offsets(stripped, token_offsets(model.tokenizer, stripped)) if stripped else [],
            "vector": [round(float(value), 6) for value in vector],
        })

    for case in cases["chunks"]:
        chunks = chunk_text(case["text"], model.tokenizer, chunk_tokens=case["chunk_tokens"], overlap=case["overlap"],
                            max_chunks=case["max_chunks"], title=case.get("title"))
        out["chunks"].append({**case, "result": [[chunk.index, chunk.text, chunk.token_count] for chunk in chunks]})

    with open(out_path, "w") as fp:
        json.dump(out, fp, ensure_ascii=False, indent=1)
        fp.write("\n")


main()
