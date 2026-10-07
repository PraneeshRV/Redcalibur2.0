"""Prove every Sigma rule: it is valid, it catches the attack, it stays quiet.

Three checks per rule:
1. the rule parses as spec-compliant Sigma (pySigma), so it is real, portable
   detection-as-code and not just YAML that happens to look right;
2. every attack sample event fires the rule (no false negatives);
3. every benign sample event stays silent (no false positives).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluator import iter_rules, load_rule, matches  # noqa: E402
from vectors import VECTORS  # noqa: E402

SIGMA_DIR = Path(__file__).resolve().parents[1] / "sigma"
RULE_PATHS = sorted(SIGMA_DIR.glob("*.yml"))
RULE_STEMS = [p.stem for p in RULE_PATHS]


def test_rules_and_vectors_line_up():
    """Every rule has a vector set and every vector set has a rule."""
    assert RULE_STEMS, "no Sigma rules found"
    assert set(RULE_STEMS) == set(VECTORS), (
        f"rules {set(RULE_STEMS)} vs vectors {set(VECTORS)}"
    )


@pytest.mark.parametrize("path", RULE_PATHS, ids=RULE_STEMS)
def test_rule_is_valid_sigma(path):
    """The rule parses under the Sigma spec via pySigma."""
    sigma = pytest.importorskip("sigma.collection")
    collection = sigma.SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    assert len(collection.rules) == 1
    rule = collection.rules[0]
    assert rule.title
    assert rule.detection.detections  # at least one selection
    assert str(rule.id)  # a UUID is present


@pytest.mark.parametrize("stem", RULE_STEMS)
def test_rule_catches_attack(stem):
    """Each attack event fires the rule (no false negatives)."""
    rule = load_rule(SIGMA_DIR / f"{stem}.yml")
    attacks = VECTORS[stem]["attack"]
    assert attacks, f"{stem} has no attack vectors"
    for event in attacks:
        assert matches(rule, event), f"{stem} missed attack event {event}"


@pytest.mark.parametrize("stem", RULE_STEMS)
def test_rule_quiet_on_benign(stem):
    """Each benign event leaves the rule silent (no false positives)."""
    rule = load_rule(SIGMA_DIR / f"{stem}.yml")
    benign = VECTORS[stem]["benign"]
    assert benign, f"{stem} has no benign vectors"
    for event in benign:
        assert not matches(rule, event), f"{stem} fired on benign event {event}"


def test_all_rules_loadable():
    """Sanity: every rule file loads and declares a condition."""
    for path, rule in iter_rules():
        assert rule["detection"]["condition"], f"{path} has no condition"
