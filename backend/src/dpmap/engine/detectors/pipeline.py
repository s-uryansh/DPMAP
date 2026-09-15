"""Detect PII in bounded text windows and return aggregate metadata only."""

from collections import defaultdict, deque
from dataclasses import dataclass
from functools import lru_cache
import re
from typing import Iterable, Iterator

import en_core_web_sm


DETECTOR_VERSION = "1.0.0"
WINDOW_SIZE = 4096
OVERLAP_SIZE = 320
NAME_CONFIDENCE_THRESHOLD = 0.75
PII_TYPES = frozenset(
    {"pan", "aadhaar", "aadhaar_masked", "phone", "email", "person_name"}
)

PAN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{5}\d{4}[A-Za-z](?![A-Za-z0-9])")
AADHAAR_RE = re.compile(r"(?<!\d)\d{4}(?:[ -]?\d{4}){2}(?!\d)")
MASKED_AADHAAR_RE = re.compile(
    r"(?<![A-Za-z0-9])x{4}(?:[ -]?x{4})[ -]?\d{4}(?!\d)", re.IGNORECASE
)
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?91[ -]?)?0?[6-9]\d{4}[ -]?\d{5}(?!\d)"
)
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9-])"
)
PAN_CONTEXT_RE = re.compile(r"\bpan\b", re.IGNORECASE)
AADHAAR_CONTEXT_RE = re.compile(r"\baadhaar\b", re.IGNORECASE)
PHONE_CONTEXT_RE = re.compile(r"\b(?:call|contact|mobile|phone)\b", re.IGNORECASE)
NAME_LABEL_RE = re.compile(
    r"\b(?:(?:employee|first|last|full)\s+)?name\s*[:=-]?\s*$", re.IGNORECASE
)

VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


@dataclass(frozen=True)
class Candidate:
    pii_type: str
    start: int
    end: int
    confidence: float
    reason_codes: tuple[str, ...]


def _near(pattern: re.Pattern[str], text: str, start: int, context: str) -> bool:
    return bool(pattern.search(f"{context} {text[max(0, start - 32):start]}"))


def _verhoeff_valid(digits: str) -> bool:
    if len(digits) != 12 or len(set(digits)) == 1:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        checksum = VERHOEFF_D[checksum][VERHOEFF_P[index % 8][int(digit)]]
    return checksum == 0


def _regex_candidates(text: str, context: str) -> Iterator[Candidate]:
    for match in PAN_RE.finditer(text):
        labelled = _near(PAN_CONTEXT_RE, text, match.start(), context)
        yield Candidate(
            "pan",
            match.start(),
            match.end(),
            0.99 if labelled else 0.85,
            ("valid_pan_shape", "pan_context") if labelled else ("valid_pan_shape",),
        )

    for match in AADHAAR_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if _verhoeff_valid(digits):
            reasons = ["valid_aadhaar_shape", "verhoeff_checksum"]
            if _near(AADHAAR_CONTEXT_RE, text, match.start(), context):
                reasons.append("aadhaar_context")
            yield Candidate(
                "aadhaar", match.start(), match.end(), 0.995, tuple(reasons)
            )

    for match in MASKED_AADHAAR_RE.finditer(text):
        reasons = ["masked_aadhaar_shape"]
        if _near(AADHAAR_CONTEXT_RE, text, match.start(), context):
            reasons.append("aadhaar_context")
        yield Candidate(
            "aadhaar_masked", match.start(), match.end(), 0.9, tuple(reasons)
        )

    for match in PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]
        labelled = _near(PHONE_CONTEXT_RE, text, match.start(), context)
        yield Candidate(
            "phone",
            match.start(),
            match.end(),
            0.98 if labelled else 0.85,
            ("indian_mobile_shape", "phone_context")
            if labelled
            else ("indian_mobile_shape",),
        )

    for match in EMAIL_RE.finditer(text):
        local, domain = match.group().rsplit("@", 1)
        if len(local) <= 64 and len(domain) <= 253:
            yield Candidate(
                "email", match.start(), match.end(), 0.98, ("valid_email_shape",)
            )


@lru_cache(maxsize=1)
def _name_pipeline():
    return en_core_web_sm.load(
        disable=["tagger", "parser", "lemmatizer", "attribute_ruler"]
    )


def _name_candidates(
    text: str, context: str, threshold: float
) -> Iterator[Candidate]:
    for entity in _name_pipeline()(text).ents:
        labelled = bool(
            NAME_LABEL_RE.search(
                f"{context} "
                f"{text[max(0, entity.start_char - 40):entity.start_char]}"
            )
        )
        if entity.label_ == "PERSON":
            confidence = 0.9 if labelled else 0.8
            reasons = (
                ("spacy_person", "name_label_context")
                if labelled
                else ("spacy_person",)
            )
        elif entity.label_ == "ORG" and labelled:
            confidence = 0.85
            reasons = ("spacy_org", "name_label_context")
        else:
            continue
        if confidence >= threshold:
            yield Candidate(
                "person_name",
                entity.start_char,
                entity.end_char,
                confidence,
                reasons,
            )


def _detect(
    text: str,
    enabled: frozenset[str],
    context: str,
    name_threshold: float,
) -> list[Candidate]:
    candidates = [
        candidate
        for candidate in _regex_candidates(text, context)
        if candidate.pii_type in enabled
    ]
    if "person_name" in enabled:
        candidates.extend(_name_candidates(text, context, name_threshold))
    return _merge_candidates(candidates)


def _merge_candidates(candidates: Iterable[Candidate]) -> list[Candidate]:
    merged: dict[tuple[str, int, int], Candidate] = {}
    for candidate in candidates:
        key = (candidate.pii_type, candidate.start, candidate.end)
        previous = merged.get(key)
        if previous is not None:
            candidate = Candidate(
                candidate.pii_type,
                candidate.start,
                candidate.end,
                max(previous.confidence, candidate.confidence),
                tuple(sorted(set(previous.reason_codes + candidate.reason_codes))),
            )
        merged[key] = candidate
    return sorted(
        merged.values(), key=lambda item: (item.start, item.end, item.pii_type)
    )


def aggregate_chunks(
    chunks: Iterable[str],
    *,
    enabled: Iterable[str] = PII_TYPES,
    context: str = "",
    name_threshold: float = NAME_CONFIDENCE_THRESHOLD,
) -> dict[str, object]:
    """Return counts and static evidence codes; source text and spans are discarded."""
    selected = frozenset(enabled)
    unknown = selected - PII_TYPES
    if unknown:
        raise ValueError(f"unknown detectors: {', '.join(sorted(unknown))}")
    if not 0 <= name_threshold <= 1:
        raise ValueError("name_threshold must be between 0 and 1")

    counts: dict[str, int] = defaultdict(int)
    confidence: dict[str, float] = defaultdict(float)
    reasons: dict[str, set[str]] = defaultdict(set)
    units_with_pii: dict[str, int] = defaultdict(int)
    last_unit: dict[str, int] = {}
    segments: deque[tuple[int, int, int]] = deque()
    buffer = ""
    buffer_offset = 0
    stream_offset = 0
    chunks_scanned = 0

    def reduce(candidates: Iterable[Candidate]) -> None:
        for candidate in candidates:
            counts[candidate.pii_type] += 1
            confidence[candidate.pii_type] = max(
                confidence[candidate.pii_type], candidate.confidence
            )
            reasons[candidate.pii_type].update(candidate.reason_codes)
            absolute_start = buffer_offset + candidate.start
            unit = next(
                index
                for start, end, index in segments
                if start <= absolute_start < end
            )
            if last_unit.get(candidate.pii_type) != unit:
                units_with_pii[candidate.pii_type] += 1
                last_unit[candidate.pii_type] = unit

    for chunk in chunks:
        if not isinstance(chunk, str):
            raise TypeError("chunks must contain strings")
        chunks_scanned += 1
        if chunk:
            segments.append(
                (stream_offset, stream_offset + len(chunk), chunks_scanned)
            )
            stream_offset += len(chunk)
        remaining = chunk
        while remaining:
            room = WINDOW_SIZE - len(buffer)
            buffer += remaining[:room]
            remaining = remaining[room:]
            if len(buffer) == WINDOW_SIZE:
                cutoff = WINDOW_SIZE - OVERLAP_SIZE
                reduce(
                    candidate
                    for candidate in _detect(
                        buffer, selected, context, name_threshold
                    )
                    if candidate.start < cutoff
                )
                buffer = buffer[cutoff:]
                buffer_offset += cutoff
                while segments and segments[0][1] <= buffer_offset:
                    segments.popleft()

    reduce(_detect(buffer, selected, context, name_threshold))
    matches = {
        pii_type: {
            "match_count": counts[pii_type],
            "units_with_pii": units_with_pii[pii_type],
            "confidence": round(confidence[pii_type], 3),
            "reason_codes": sorted(reasons[pii_type]),
        }
        for pii_type in sorted(counts)
    }
    return {
        "schema_version": "1.0.0",
        "detector_version": DETECTOR_VERSION,
        "chunks_scanned": chunks_scanned,
        "total_matches": sum(counts.values()),
        "matches": matches,
    }
