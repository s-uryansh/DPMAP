import json
from pathlib import Path

import en_core_web_sm
from jsonschema import Draft202012Validator

from dpmap.main import app, health


FIXTURES = Path(__file__).parent / "fixtures"


def test_health_endpoint() -> None:
    route = next(
        route for route in app.routes if getattr(route, "path", None) == "/health"
    )
    assert route.endpoint() == {"status": "ok", "version": "0.1.0"}
    assert health() == {"status": "ok", "version": "0.1.0"}


def test_quality_corpus_matches_its_schema() -> None:
    schema = json.loads((FIXTURES / "pii-corpus.schema.json").read_text())
    corpus = json.loads((FIXTURES / "pii-corpus.v1.json").read_text())

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(corpus)


def test_pinned_spacy_model_loads() -> None:
    assert en_core_web_sm.load().meta["version"] == "3.8.0"
