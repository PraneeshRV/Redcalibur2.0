"""Minimal, offline Sigma rule evaluator.

Purpose: a hermetic test oracle so each detection rule can be proven to fire on
an attack event and stay silent on benign activity, without a SIEM or network
backend. It interprets the subset of the Sigma specification the rules in
``detections/sigma`` actually use:

* field matching with value lists (OR) and the ``|contains``, ``|startswith``,
  ``|endswith``, ``|all``, ``|re`` and ``|cidr`` modifiers;
* named selections (a mapping is an AND over its fields);
* a condition mini-language: ``and`` / ``or`` / ``not`` / parentheses, plus the
  ``1 of <pattern>``, ``all of <pattern>``, ``1 of them`` and ``all of them``
  aggregations, where ``<pattern>`` is a selection name or ``prefix*`` glob.

It is deliberately not a full Sigma engine. pySigma validates that the rules are
spec-compliant (see the test suite); this module only decides "does event X
match rule Y" for the test vectors.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

SIGMA_DIR = Path(__file__).resolve().parent / "sigma"


def load_rule(path: str | Path) -> dict[str, Any]:
    """Load a single Sigma rule YAML file into a dict."""
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def iter_rules(directory: str | Path = SIGMA_DIR):
    """Yield (path, rule) for every ``*.yml`` rule under *directory*."""
    for path in sorted(Path(directory).glob("*.yml")):
        yield path, load_rule(path)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _match_scalar(modifier: str | None, event_value: Any, expected: Any) -> bool:
    """Match one expected value against one event value under *modifier*."""
    if event_value is None:
        return False

    if modifier == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
            return ipaddress.ip_address(str(event_value)) in net
        except ValueError:
            return False

    if modifier == "re":
        return re.search(str(expected), str(event_value)) is not None

    ev = str(event_value)
    exp = str(expected)
    # Sigma string matching is case-insensitive.
    ev_l, exp_l = ev.lower(), exp.lower()

    if modifier == "contains":
        return exp_l in ev_l
    if modifier == "startswith":
        return ev_l.startswith(exp_l)
    if modifier == "endswith":
        return ev_l.endswith(exp_l)

    # Plain equality: numbers compare numerically, everything else as text.
    if isinstance(expected, bool) or isinstance(event_value, bool):
        return bool(event_value) == bool(expected)
    if isinstance(expected, (int, float)) and not isinstance(event_value, str):
        try:
            return float(event_value) == float(expected)
        except (TypeError, ValueError):
            return False
    return ev_l == exp_l


def _match_field(key: str, expected: Any, event: dict[str, Any]) -> bool:
    """Match a single ``field`` or ``field|modifier`` entry against the event."""
    field, _, modifier = key.partition("|")
    modifier = modifier or None
    event_value = event.get(field)

    expected_values = _as_list(expected)
    # ``|all`` means every listed value must match; otherwise any (OR).
    reducer = all if modifier == "all" else any
    core_modifier = None if modifier == "all" else modifier
    return reducer(
        _match_scalar(core_modifier, event_value, exp) for exp in expected_values
    )


def _match_selection(selection: Any, event: dict[str, Any]) -> bool:
    """A selection is an AND over its fields; a list of selections is an OR."""
    if isinstance(selection, list):
        return any(_match_selection(item, event) for item in selection)
    if isinstance(selection, dict):
        return all(_match_field(key, val, event) for key, val in selection.items())
    # A bare keyword selection (plain string) is unsupported by our rules.
    raise ValueError(f"Unsupported selection shape: {selection!r}")


def _resolve_names(pattern: str, names: list[str]) -> list[str]:
    if pattern == "them":
        return [n for n in names if n != "condition"]
    if pattern.endswith("*"):
        return [n for n in names if fnmatch.fnmatchcase(n, pattern)]
    return [n for n in names if n == pattern]


def _eval_condition(condition: str, detection: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate the condition string into a boolean for *event*.

    Selections are matched up front into booleans, then the condition is
    tokenised and rewritten into a pure boolean expression (only ``True`` /
    ``False`` literals and ``and`` / ``or`` / ``not`` / parentheses reach
    ``eval``), so selection names can never be mistaken for Python code.
    """
    names = [n for n in detection if n != "condition"]
    results = {n: _match_selection(detection[n], event) for n in names}

    tokens = re.findall(r"[A-Za-z0-9_]+\*?|\(|\)", condition)
    out: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"and", "or", "not", "(", ")"}:
            out.append(token)
            i += 1
        elif token in {"1", "all"} and i + 2 < len(tokens) and tokens[i + 1] == "of":
            resolved = _resolve_names(tokens[i + 2], names)
            vals = [results[n] for n in resolved]
            agg = any(vals) if token == "1" else (bool(vals) and all(vals))
            out.append("True" if agg else "False")
            i += 3
        else:
            out.append("True" if results.get(token, False) else "False")
            i += 1

    return bool(eval(" ".join(out), {"__builtins__": {}}, {}))  # noqa: S307


def matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    """Return True if *event* satisfies *rule*'s detection condition."""
    detection = rule["detection"]
    condition = detection["condition"]
    if not isinstance(condition, str):
        raise ValueError("Only single string conditions are supported.")
    return _eval_condition(condition, detection, event)
