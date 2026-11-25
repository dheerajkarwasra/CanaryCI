"""Export and verify offline, tamper-evident audit archives."""

import base64
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from typing import Literal
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jinja2 import Environment
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..core.errors import AuditVerificationError, ConfigurationError
from ..core.models import OwaspCategory
from ..runner.suite_runner import SuiteRunSummary, replay_trace_file
from .markdown_pr import load_json_summary

_DEFAULTS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "ASI01": (("MEASURE 2.6", "MEASURE 2.7", "MANAGE 2.4"), ("Art. 15(4)", "Art. 55(1)(d)")),
    "ASI02": (("MEASURE 2.7", "MANAGE 1.3"), ("Art. 15(5)",)),
    "ASI03": (("GOVERN 1.2", "MEASURE 2.7"), ("Art. 15(4)", "Art. 14")),
    "ASI04": (("MAP 4.1", "GOVERN 6.1", "MEASURE 2.7"), ("Art. 15(5)", "Art. 25")),
    "ASI05": (("MEASURE 2.6", "MANAGE 2.4"), ("Art. 15(4)", "Art. 15(5)")),
    "ASI06": (("MEASURE 2.7", "MANAGE 2.2"), ("Art. 10", "Art. 15(5)")),
    "ASI07": (("MAP 4.1", "MEASURE 2.7"), ("Art. 15(5)",)),
    "ASI08": (("MEASURE 2.6", "MANAGE 2.4"), ("Art. 15(4)", "Art. 55")),
    "ASI09": (("GOVERN 1.4", "MEASURE 2.8"), ("Art. 14",)),
    "ASI10": (("MEASURE 2.6", "MANAGE 2.4", "MANAGE 4.1"), ("Art. 14(4)(e)", "Art. 15(4)")),
}
_REQUIRED: frozenset[str] = frozenset(
    {
        "summary.json",
        "results.sarif.json",
        "public_key.pem",
        "compliance_report.md",
        "compliance_report.html",
    }
)
_SCENARIO_ID = re.compile(r"[a-z0-9][a-z0-9_-]{3,63}")
_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CanaryCI controls</title>
<style>body{font-family:system-ui;max-width:70rem;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:.4rem;text-align:left}
</style></head><body><h1>CanaryCI control cross-references</h1><p>Run {{ run_id }}</p>
<p>Results describe observed behavior in the listed fixtures.</p>
<table><thead><tr>{% for header in headers %}<th>{{ header }}</th>{% endfor %}</tr></thead>
<tbody>{% for row in rows %}<tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>
{% endfor %}</tbody>
</table><h2>Active waivers</h2><ul>{% for waiver in waivers %}<li>{{ waiver }}</li>
{% else %}<li>None recorded</li>{% endfor %}</ul></body></html>"""


class _ManifestEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class AuditManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[1] = 1
    run_id: str
    key_origin: Literal["configured", "ephemeral"]
    files: dict[str, _ManifestEntry]


class AuditVerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    run_id: str
    verified_files: int
    key_origin: Literal["configured", "ephemeral"]
    trusted_key_used: bool


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def generate_ed25519_keypair(out_prefix: Path) -> tuple[Path, Path]:
    private_path, public_path = Path(f"{out_prefix}.key"), Path(f"{out_prefix}.pub")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    created: list[Path] = []
    try:
        private_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(private_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        created.append(private_path)
        with os.fdopen(fd, "wb") as handle:
            handle.write(private)
        with public_path.open("xb") as handle:
            created.append(public_path)
            handle.write(_public_bytes(key.public_key()))
    except OSError as exc:
        for path in created:
            path.unlink(missing_ok=True)
        raise ConfigurationError(f"Cannot create signing keypair at {out_prefix}") from exc
    return private_path, public_path


def read_signing_key(value: str) -> bytes:
    return value.encode() if value.lstrip().startswith("-----BEGIN ") else Path(value).read_bytes()


def _key(pem: bytes | None) -> tuple[Ed25519PrivateKey, Literal["configured", "ephemeral"]]:
    try:
        if pem is None and (configured := os.getenv("CANARY_SIGNING_PRIVATE_KEY")):
            pem = read_signing_key(configured)
        if pem is None:
            return Ed25519PrivateKey.generate(), "ephemeral"
        key = serialization.load_pem_private_key(pem, password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        raise ConfigurationError("Invalid Ed25519 private signing key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigurationError("Expected an Ed25519 private signing key")
    return key, "configured"


def _read_run_file(root: Path, relative: Path) -> bytes:
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ConfigurationError("Audit run contains a file outside the run directory")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"Missing audit input {relative}") from exc


def _compliance(
    summary: SuiteRunSummary,
    controls: dict[str, tuple[list[str], list[str]]],
) -> tuple[bytes, bytes]:
    counts: Counter[tuple[str, str]] = Counter()
    waivers = []
    for outcome in summary.outcomes:
        if outcome.owasp_category:
            breached = any(not trial.passed for trial in outcome.trials)
            status = "waived" if outcome.waived else "breached" if breached else "clean"
            counts[outcome.owasp_category, status] += 1
        if outcome.waiver is not None:
            waiver = outcome.waiver
            waivers.append(
                f"{waiver.scenario_id} · {waiver.owner} · {waiver.expires_at} · {waiver.reason}"
            )
    headers = ["OWASP", "Clean", "Breached", "Waived", "NIST AI RMF 1.0", "EU AI Act"]
    rows = [
        [
            category.value,
            *(str(counts[category, status]) for status in ("clean", "breached", "waived")),
            *(
                ", ".join(dict.fromkeys([*defaults, *extra]))
                for defaults, extra in zip(
                    _DEFAULTS[category], controls.get(category, ([], [])), strict=True
                )
            ),
        ]
        for category in OwaspCategory
    ]
    html = (
        Environment(autoescape=True)
        .from_string(_HTML)
        .render(
            run_id=summary.run_id,
            headers=headers,
            rows=rows,
            waivers=waivers,
        )
    )

    def markdown_text(value: str) -> str:
        return " ".join(value.split()).replace("<", "&lt;").replace("|", "&#124;")

    lines = [
        "# CanaryCI control cross-references",
        "",
        f"Run {markdown_text(summary.run_id)}",
        "",
        "Results describe observed behavior in the listed fixtures.",
        "",
        "| " + " | ".join(headers) + " |",
        "| --- | ---: | ---: | ---: | --- | --- |",
    ]
    lines.extend("| " + " | ".join(map(markdown_text, row)) + " |" for row in rows)
    lines.extend(["", "## Active waivers", ""])
    lines.extend(f"- {markdown_text(waiver)}" for waiver in (waivers or ["None recorded"]))
    return ("\n".join(lines) + "\n").encode(), html.encode()


def export_signed_audit_bundle(
    run_dir: Path,
    out_zip: Path,
    private_key_pem: bytes | None = None,
) -> Path:
    root = run_dir.resolve()
    entries = {
        name: _read_run_file(root, Path(name)) for name in ("summary.json", "results.sarif.json")
    }
    summary = load_json_summary(root / "summary.json")
    key, origin = _key(private_key_pem)
    controls: dict[str, tuple[list[str], list[str]]] = {}
    for outcome in summary.outcomes:
        if not _SCENARIO_ID.fullmatch(outcome.scenario_id):
            raise ConfigurationError("Audit summary contains an invalid scenario ID")
        for trial in outcome.trials:
            if trial.trial_index < 0:
                raise ConfigurationError("Audit summary contains an invalid trial index")
            relative = Path(outcome.scenario_id) / f"trial_{trial.trial_index}.trace.jsonl"
            entries[f"traces/{relative.as_posix()}"] = _read_run_file(root, relative)
        if outcome.trials:
            first = outcome.trials[0]
            trace = root / outcome.scenario_id / f"trial_{first.trial_index}.trace.jsonl"
            scenario = replay_trace_file(trace).scenario
            if scenario.compliance:
                nist, eu = controls.setdefault(scenario.owasp_category, ([], []))
                nist.extend(scenario.compliance.nist_ai_rmf)
                eu.extend(scenario.compliance.eu_ai_act)
    entries["compliance_report.md"], entries["compliance_report.html"] = _compliance(
        summary, controls
    )
    entries["public_key.pem"] = _public_bytes(key.public_key())
    manifest = AuditManifest(
        run_id=summary.run_id,
        key_origin=origin,
        files={
            name: _ManifestEntry(sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
            for name, data in entries.items()
        },
    )
    manifest_bytes = json.dumps(
        manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    entries["manifest.json"] = manifest_bytes
    entries["manifest.sig"] = base64.b64encode(key.sign(manifest_bytes))
    temp_path: Path | None = None
    try:
        out_zip.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=out_zip.parent, suffix=".zip", delete=False) as handle:
            temp_path = Path(handle.name)
        with ZipFile(temp_path, "w") as archive:
            for name, value in sorted(entries.items()):
                archive.writestr(ZipInfo(name), value, compress_type=ZIP_DEFLATED)
        os.link(temp_path, out_zip)
    except OSError as exc:
        raise ConfigurationError(f"Cannot write audit archive at {out_zip}") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return out_zip


def _normal_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(path.parts)
        and path.as_posix() == name
        and not (path.is_absolute() or ".." in path.parts or "\\" in name)
    )


def verify_signed_audit_bundle(
    bundle_zip: Path,
    trusted_public_key_pem: bytes | None = None,
) -> AuditVerificationResult:
    try:
        with ZipFile(bundle_zip) as bundle:
            names = bundle.namelist()
            if len(names) != len(set(names)) or not all(map(_normal_member, names)):
                raise AuditVerificationError("Audit archive contains invalid member paths")
            manifest_bytes = bundle.read("manifest.json")
            public = (
                trusted_public_key_pem
                if trusted_public_key_pem is not None
                else bundle.read("public_key.pem")
            )
            key = serialization.load_pem_public_key(public)
            if not isinstance(key, Ed25519PublicKey):
                raise AuditVerificationError("Expected an Ed25519 public key")
            key.verify(base64.b64decode(bundle.read("manifest.sig"), validate=True), manifest_bytes)
            manifest = AuditManifest.model_validate_json(manifest_bytes)
            if not _REQUIRED.issubset(manifest.files) or set(names) != (
                manifest.files.keys() | {"manifest.json", "manifest.sig"}
            ):
                raise AuditVerificationError("Audit archive has missing or unlisted files")
            for name, expected in manifest.files.items():
                digest = hashlib.sha256()
                with bundle.open(name) as handle:
                    for chunk in iter(lambda: handle.read(64 * 1024), b""):
                        digest.update(chunk)
                if (
                    bundle.getinfo(name).file_size != expected.size_bytes
                    or digest.hexdigest() != expected.sha256
                ):
                    raise AuditVerificationError(f"Audit integrity check failed for {name}")
    except InvalidSignature:
        raise AuditVerificationError("Audit signature verification failed") from None
    except (
        OSError,
        BadZipFile,
        ValueError,
        TypeError,
        KeyError,
        RuntimeError,
        UnsupportedAlgorithm,
        ValidationError,
    ):
        raise AuditVerificationError("Invalid audit archive or signing key") from None
    return AuditVerificationResult(
        valid=True,
        run_id=manifest.run_id,
        verified_files=len(manifest.files),
        key_origin=manifest.key_origin,
        trusted_key_used=trusted_public_key_pem is not None,
    )
