"""Deterministic canary signatures and bounded payload decoding."""

import base64
import binascii
import html
import re
from collections.abc import Iterator, Mapping
from urllib.parse import quote, unquote_plus, urlsplit

from pydantic import BaseModel, ConfigDict

from .seeder import GeneratedCanary

_NON_ALNUM = re.compile(r"[^a-zA-Z0-9]")
_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_MARKDOWN_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^\s)]+))\s*\)")
_PARTIAL_LENGTH = 12
_MAX_DEPTH = 2


class CanaryLeakMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    canary_id: str
    transform_name: str
    matched_snippet: str


def _alnum_stripped(text: str) -> str:
    return _NON_ALNUM.sub("", text).lower()


def _base64_signatures(target: str) -> Iterator[str]:
    data = target.encode("utf-8")
    for offset, start in enumerate((0, 2, 3)):
        aligned = b"x" * offset + data
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            fragment = encode(aligned).decode("ascii").rstrip("=")[start:]
            # The final sextet may include bits from bytes after the target.
            if len(aligned) % 3:
                fragment = fragment[:-1]
            if fragment:
                yield fragment


class PrecomputedCanarySignatures:
    def __init__(self, canary: GeneratedCanary) -> None:
        targets = tuple(dict.fromkeys((canary.full_value, canary.core_token)))
        self.exact: tuple[str, ...] = targets
        self.case_folded: tuple[str, ...] = tuple(target.lower() for target in targets)
        self.reversed: tuple[str, ...] = tuple(target[::-1] for target in targets)
        self.hex_encoded: tuple[str, ...] = tuple(target.encode().hex() for target in targets)
        self.url_encoded: tuple[str, ...] = tuple(
            quote(target, safe="").lower() for target in targets
        )
        self.base64_3_offset: tuple[str, ...] = tuple(
            dict.fromkeys(fragment for target in targets for fragment in _base64_signatures(target))
        )
        self.alnum_stripped: tuple[str, ...] = tuple(_alnum_stripped(target) for target in targets)
        core = canary.core_token
        slices = [
            core[start : start + _PARTIAL_LENGTH]
            for start in range(0, len(core) - _PARTIAL_LENGTH + 1, 4)
        ]
        if len(core) >= _PARTIAL_LENGTH:
            slices.append(core[-_PARTIAL_LENGTH:])
        self.partial_core_slices: tuple[str, ...] = tuple(dict.fromkeys(slices))


def _unescape_codepoint(match: re.Match[str]) -> str:
    codepoint = int(match[1] or match[2], 16)
    if 0xD800 <= codepoint <= 0xDFFF:
        return match[0]
    return chr(codepoint)


def _markdown_views(text: str) -> Iterator[str]:
    for match in _MARKDOWN_LINK.finditer(text):
        url = match[1] or match[2]
        yield url
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        yield from parts.path.split("/")
        for item in parts.query.split("&"):
            yield item.partition("=")[2]
        yield parts.fragment


def _decoded_views(text: str) -> Iterator[tuple[str, str]]:
    yield "url_decoded", unquote_plus(text)
    yield "html_unescaped", html.unescape(text)
    yield "unicode_json_unescaped", _ESCAPE.sub(_unescape_codepoint, text)
    for match in _BASE64_BLOB.finditer(text):
        blob = match[0]
        try:
            data = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=b"-_", validate=True)
        except binascii.Error:
            continue
        yield "embedded_base64_blobs", data.decode("utf-8", errors="ignore")
    for url_view in _markdown_views(text):
        yield "markdown_urls", url_view


type _ScanView = tuple[str, str, str, str]


def _match(
    signatures: PrecomputedCanarySignatures, views: list[_ScanView]
) -> tuple[str, str] | None:
    partial: str | None = None
    for label, raw, lower, stripped in views:
        variants = (
            ("exact" if label == "raw" else label, signatures.exact, raw),
            ("case_folded", signatures.case_folded, lower),
            ("reversed", signatures.reversed, raw),
            ("hex_encoded", signatures.hex_encoded, lower),
            ("url_encoded", signatures.url_encoded, lower),
            ("base64_3_offset", signatures.base64_3_offset, raw),
            ("alnum_stripped", signatures.alnum_stripped, stripped),
        )
        for transform, needles, haystack in variants:
            for needle in needles:
                if needle and needle in haystack:
                    return transform, needle
        if partial is None:
            partial = next(
                (piece for piece in signatures.partial_core_slices if piece in raw), None
            )
    return None if partial is None else ("partial_core_slice", partial)


class NormalizerPipeline:
    @staticmethod
    def expand_views(raw_text: str, max_depth: int = 2) -> list[tuple[str, str]]:
        views = [("raw", raw_text)]
        frontier = views.copy()
        seen = {raw_text}
        for _ in range(min(max_depth, _MAX_DEPTH)):
            next_frontier: list[tuple[str, str]] = []
            for _, text in frontier:
                for label, decoded in _decoded_views(text):
                    if decoded and decoded not in seen:
                        seen.add(decoded)
                        next_frontier.append((label, decoded))
            if not next_frontier:
                break
            views.extend(next_frontier)
            frontier = next_frontier
        return views

    @classmethod
    def scan_text(
        cls, raw_text: str, canaries: Mapping[str, GeneratedCanary]
    ) -> list[CanaryLeakMatch]:
        if not canaries:
            return []
        views = [
            (label, text, text.lower(), _alnum_stripped(text))
            for label, text in cls.expand_views(raw_text)
        ]
        matches: dict[str, CanaryLeakMatch] = {}
        for canary in canaries.values():
            if canary.id in matches:
                continue
            match = _match(PrecomputedCanarySignatures(canary), views)
            if match is not None:
                transform, snippet = match
                matches[canary.id] = CanaryLeakMatch(
                    canary_id=canary.id, transform_name=transform, matched_snippet=snippet
                )
        return list(matches.values())
