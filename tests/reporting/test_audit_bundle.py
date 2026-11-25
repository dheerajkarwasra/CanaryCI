from pathlib import Path
from zipfile import ZipFile

import pytest
from typer.testing import CliRunner

from canary_ci.cli.app import app
from canary_ci.core.errors import AuditVerificationError
from canary_ci.reporting.markdown_pr import load_json_summary


def test_audit_cli_signs_and_validates_every_archive_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from canary_ci.reporting.audit_bundle import verify_signed_audit_bundle

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, ["init", "--demo"]).exit_code == 0
    result = runner.invoke(
        app, ["run", "--config", "canary.demo.yaml", "--json-report", "run.json"]
    )
    assert result.exit_code == 1, result.output
    run = load_json_summary(Path("run.json"))
    run_dir = Path(".canary") / "runs" / run.run_id
    keygen = runner.invoke(app, ["audit", "keygen", "--out-prefix", "fixture"])
    assert keygen.exit_code == 0, keygen.output
    assert Path("fixture.key").stat().st_mode & 0o777 == 0o600
    exported = runner.invoke(
        app,
        [
            "audit",
            "export",
            "--run-dir",
            str(run_dir),
            "--signing-key",
            "fixture.key",
            "--out",
            "audit.zip",
        ],
    )
    assert exported.exit_code == 0, exported.output
    verified = runner.invoke(app, ["audit", "verify", "audit.zip", "--public-key", "fixture.pub"])
    assert verified.exit_code == 0, verified.output
    with ZipFile("audit.zip") as source, ZipFile("modified.zip", "w") as modified:
        html = source.read("compliance_report.html").decode()
        assert all(label in html for label in ("ASI01", "MEASURE", "Art. 15"))
        for name in source.namelist():
            value = source.read(name)
            if name == "compliance_report.md":
                value = bytes([value[0] ^ 1]) + value[1:]
            modified.writestr(name, value)
    with pytest.raises(AuditVerificationError, match="compliance_report.md"):
        verify_signed_audit_bundle(Path("modified.zip"))
    assert runner.invoke(app, ["audit", "keygen", "--out-prefix", "other"]).exit_code == 0
    with pytest.raises(AuditVerificationError, match="signature"):
        verify_signed_audit_bundle(Path("audit.zip"), Path("other.pub").read_bytes())
    assert runner.invoke(app, ["audit", "verify", "modified.zip"]).exit_code == 1
