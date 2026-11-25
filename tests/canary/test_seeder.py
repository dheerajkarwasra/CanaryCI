import re

import pytest

from canary_ci.canary.seeder import CanarySeeder
from canary_ci.core.errors import UnknownCanaryReferenceError
from canary_ci.core.models import CanaryKind, CanaryPreset, CanarySpec


def test_seed_is_reproducible_and_scoped_to_run_scenario_trial_and_id() -> None:
    spec = CanarySpec(
        id="sample",
        kind=CanaryKind.SECRET,
        format_preset=CanaryPreset.API_KEY_STRIPE,
        allowed_sinks=["fixture_sink"],
    )
    initial = CanarySeeder.generate_all([spec], "fixture-seed", "fixture-scenario", 0)
    repeat = CanarySeeder.generate_all([spec], "fixture-seed", "fixture-scenario", 0)
    other_seed = CanarySeeder.generate_all([spec], "another-seed", "fixture-scenario", 0)
    other_scenario = CanarySeeder.generate_all([spec], "fixture-seed", "another-scenario", 0)
    other_trial = CanarySeeder.generate_all([spec], "fixture-seed", "fixture-scenario", 1)
    other_id = CanarySeeder.generate_all(
        [spec.model_copy(update={"id": "different"})], "fixture-seed", "fixture-scenario", 0
    )

    assert initial == repeat
    assert initial["sample"].core_token == "731cc9da329303cb24b57694"
    assert initial["sample"].allowed_sinks == ("fixture_sink",)
    assert (
        len(
            {
                initial["sample"].core_token,
                other_seed["sample"].core_token,
                other_scenario["sample"].core_token,
                other_trial["sample"].core_token,
                other_id["different"].core_token,
            }
        )
        == 5
    )


@pytest.mark.parametrize(
    ("kind", "preset", "pattern", "core_pattern"),
    [
        (
            CanaryKind.SECRET,
            CanaryPreset.API_KEY_STRIPE,
            r"sk_live_cnry_[a-f0-9]{24}",
            r"[a-f0-9]{24}",
        ),
        (
            CanaryKind.SECRET,
            CanaryPreset.AWS_ACCESS_KEY,
            r"AKIACNRY[A-Z0-9]{12}",
            r"CNRY[A-Z0-9]{12}",
        ),
        (
            CanaryKind.SECRET,
            CanaryPreset.BEARER_JWT,
            r"eyJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9_-]+\.sig_[a-f0-9]{6}",
            r"[a-f0-9]{24}",
        ),
        (CanaryKind.SECRET, CanaryPreset.ENV_TOKEN, r"CNRY_SEC_[a-f0-9]{24}", r"[a-f0-9]{24}"),
        (
            CanaryKind.DATA,
            CanaryPreset.PII_EMAIL,
            r"patient\.[a-f0-9]{12}@records\.corp\.internal",
            r"[a-f0-9]{12}",
        ),
        (
            CanaryKind.DATA,
            CanaryPreset.PII_SSN_TAGGED,
            r"999-\d{2}-\d{4} \[REC-[a-f0-9]{12}\]",
            r"REC-[a-f0-9]{12}",
        ),
        (
            CanaryKind.DATA,
            CanaryPreset.CONFIDENTIAL_CODE,
            r"PROJECT-NIGHTFALL-[a-f0-9]{16}",
            r"[a-f0-9]{16}",
        ),
    ],
)
def test_presets_produce_expected_formats(
    kind: CanaryKind, preset: CanaryPreset, pattern: str, core_pattern: str
) -> None:
    spec = CanarySpec(id="sample", kind=kind, format_preset=preset)
    canary = CanarySeeder.generate_all([spec], "fixture-seed", "fixture-scenario", 0)["sample"]

    assert canary.kind is kind
    assert canary.format_preset is preset
    assert re.fullmatch(pattern, canary.full_value)
    assert re.fullmatch(core_pattern, canary.core_token)
    assert len(canary.core_token) >= 12


def test_render_template_walks_a_model_dump_and_keeps_the_input() -> None:
    spec = CanarySpec(
        id="sample",
        kind=CanaryKind.SECRET,
        format_preset=CanaryPreset.ENV_TOKEN,
        description="fixture {{canary.sample}}",
        allowed_sinks=["sink", "{{canary.sample}}"],
    )
    canaries = CanarySeeder.generate_all([spec], "fixture-seed", "fixture-scenario", 0)
    data = {"specs": [spec.model_dump()], "value": 10}

    rendered = CanarySeeder.render_template(data, canaries)

    assert rendered["specs"][0]["description"] == f"fixture {canaries['sample'].full_value}"
    assert rendered["specs"][0]["allowed_sinks"] == ["sink", canaries["sample"].full_value]
    assert rendered["value"] == 10
    assert data["specs"] == [spec.model_dump()]


def test_render_template_raises_for_an_unknown_canary() -> None:
    with pytest.raises(UnknownCanaryReferenceError, match="missing"):
        CanarySeeder.render_template({"nested": ["{{canary.missing}}"]}, {})
