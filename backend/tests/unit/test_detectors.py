import json
from pathlib import Path

import pytest

from dpmap.engine.detectors import aggregate_chunks
from dpmap.engine.detectors.pipeline import Candidate, _merge_candidates


FIXTURES = Path(__file__).parents[1] / "fixtures"
RULES = (
    Path(__file__).parents[2]
    / "src/dpmap/engine/assessment/rules.v1.json"
)
FAMILY_TYPES = {
    "pan": {"pan"},
    "aadhaar": {"aadhaar", "aadhaar_masked"},
    "phone": {"phone"},
    "email": {"email"},
    "person_name": {"person_name"},
}


def test_frozen_corpus_meets_detector_rate_thresholds() -> None:
    corpus = json.loads((FIXTURES / "pii-corpus.v1.json").read_text())
    gates = json.loads(RULES.read_text())["detector_release_gates"]
    totals = {
        name: {"tp": 0, "fp": 0, "fn": 0} for name in FAMILY_TYPES
    }

    for case in corpus["cases"]:
        selected = FAMILY_TYPES if case["detector"] == "mixed" else [case["detector"]]
        result = aggregate_chunks([case["text"]], enabled={
            pii_type
            for detector in selected
            for pii_type in FAMILY_TYPES[detector]
        })
        actual = {
            pii_type: item["match_count"]
            for pii_type, item in result["matches"].items()
        }
        expected = {item["type"]: item["count"] for item in case["expected"]}
        assert actual == expected, case["id"]

        for detector in selected:
            actual_count = sum(actual.get(kind, 0) for kind in FAMILY_TYPES[detector])
            expected_count = sum(
                expected.get(kind, 0) for kind in FAMILY_TYPES[detector]
            )
            totals[detector]["tp"] += min(actual_count, expected_count)
            totals[detector]["fp"] += max(0, actual_count - expected_count)
            totals[detector]["fn"] += max(0, expected_count - actual_count)

    for detector, metrics in totals.items():
        precision = metrics["tp"] / (metrics["tp"] + metrics["fp"])
        recall = metrics["tp"] / (metrics["tp"] + metrics["fn"])
        assert precision >= gates[detector]["min_precision"]
        assert recall >= gates[detector]["min_recall"]


def test_chunk_boundaries_are_counted_once() -> None:
    result = aggregate_chunks(
        ["x" * 4070 + " audit@example.", "in" + " " * 400],
        enabled={"email"},
    )

    assert result["chunks_scanned"] == 2
    assert result["total_matches"] == 1
    assert result["matches"]["email"]["match_count"] == 1


def test_identifier_context_changes_evidence_without_changing_counts() -> None:
    result = aggregate_chunks(
        ["999999990019 xxxx-xxxx-0019 9876543210"],
        enabled={"aadhaar", "aadhaar_masked", "phone"},
    )

    assert result["total_matches"] == 3
    assert result["matches"]["phone"]["confidence"] == 0.85
    assert "aadhaar_context" not in result["matches"]["aadhaar"]["reason_codes"]
    assert "aadhaar_context" not in result["matches"]["aadhaar_masked"]["reason_codes"]


def test_aggregate_serialization_discards_source_values_and_coordinates() -> None:
    source_values = (
        "ABCDE1234F",
        "9999 9999 0019",
        "+91 98765 43210",
        "audit+plant@example.com",
        "Kavya Sharma",
    )
    result = aggregate_chunks(
        [
            "PAN ABCDE1234F; Aadhaar 9999 9999 0019; contact "
            "+91 98765 43210; email audit+plant@example.com; "
            "employee name: Kavya Sharma"
        ]
    )
    serialized = json.dumps(result)

    assert result["total_matches"] == 5
    assert all(value not in serialized for value in source_values)
    assert not {"text", "value", "start", "end", "excerpt", "hash"} & set(
        serialized.replace('"', "").replace(":", ",").split(",")
    )


def test_detector_selection_and_input_validation() -> None:
    assert aggregate_chunks([], enabled={"pan"})["total_matches"] == 0
    assert aggregate_chunks(["PAN ABCDE1234F"], enabled=set())["total_matches"] == 0
    assert aggregate_chunks(
        ["Reviewed by Arjun Mehta"], name_threshold=1.0
    )["total_matches"] == 0
    repeated = aggregate_chunks(
        ["first@example.in second@example.in", ""], enabled={"email"}
    )
    assert repeated["matches"]["email"]["units_with_pii"] == 1
    with pytest.raises(ValueError, match="unknown detectors"):
        aggregate_chunks(["anything"], enabled={"passport"})
    with pytest.raises(ValueError, match="name_threshold"):
        aggregate_chunks(["anything"], name_threshold=1.1)
    with pytest.raises(TypeError, match="chunks must contain strings"):
        aggregate_chunks([b"not text"])


def test_duplicate_candidates_merge_without_retaining_values() -> None:
    merged = _merge_candidates(
        [
            Candidate("email", 4, 20, 0.8, ("shape",)),
            Candidate("email", 4, 20, 0.98, ("context",)),
        ]
    )

    assert merged == [
        Candidate("email", 4, 20, 0.98, ("context", "shape"))
    ]
    assert aggregate_chunks(
        ["a" * 65 + "@example.com"], enabled={"email"}
    )["total_matches"] == 0
