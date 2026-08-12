#!/usr/bin/env python3
"""Local checks for the Semgrep rules and their fixtures.

This is NOT a substitute for `semgrep --test` -- it cannot evaluate whether a
pattern actually matches, because that requires Semgrep's matching engine.
It verifies everything else, so that when Semgrep can be installed the only
open question is pattern matching itself:

  1. each YAML parses and carries the fields Semgrep requires
  2. taint rules declare both pattern-sources and pattern-sinks
  3. the rule id matches its filename, and ids are unique across the ruleset
  4. every `// ruleid:` / `// ok:` annotation names a rule that exists
  5. each annotation sits directly above a non-comment line of code
  6. the fixtures compile with javac (proving they are real Java)

Exit code is non-zero if any check fails.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

import yaml

HERE = pathlib.Path(__file__).parent
REQUIRED = ("id", "message", "severity", "languages")
VALID_SEVERITY = {"ERROR", "WARNING", "INFO"}
VALID_LANGUAGES = ({"java"}, {"generic"})

# Two fixture styles: `.java` fixtures use `//` line comments (Semgrep's own
# `--test` annotation convention for that language); `.xml` fixtures (the
# `languages: [generic]` / `pattern-regex` rules -- the dangerous pattern
# lives in XML config content, not Java source, so there's no AST for those
# rules to match against) use `<!-- -->` comments instead, since that's what
# Semgrep's test runner recognizes for non-`//`-comment file types.
ANNOT_BY_SUFFIX = {
    ".java": re.compile(r"//\s*(ruleid|ok|todoruleid|todook):\s*([A-Za-z0-9_.-]+)"),
    ".xml": re.compile(r"<!--\s*(ruleid|ok|todoruleid|todook):\s*([A-Za-z0-9_.-]+)\s*-->"),
}
COMMENT_PREFIX_BY_SUFFIX = {".java": "//", ".xml": "<!--"}

failures: list[str] = []
notes: list[str] = []


class _DuplicateKeyLoader(yaml.SafeLoader):
    """PyYAML's SafeLoader silently lets a later key win on duplicates --
    ruamel.yaml (what Semgrep itself parses rules with) raises instead. A
    rule with e.g. two `impact:` keys under the same `metadata:` block
    parses "successfully" here and only breaks in CI, one YAML-parser
    behavioral difference away from being caught locally. Found the hard
    way (a real CI failure: ruamel.yaml.constructor.DuplicateKeyError),
    fixed by matching ruamel's strictness here instead of just moving on."""


def _construct_mapping_no_dupes(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_dupes
)


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"  [FAIL] {msg}")


def ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def section(msg: str) -> None:
    print(f"\n--- {msg} ---")


# ------------------------------------------------------------------ 1-3. rules
section("rule definitions")

rule_ids: dict[str, pathlib.Path] = {}
yaml_files = sorted(HERE.glob("*.yaml"))
if not yaml_files:
    fail("no .yaml rule files found")

for path in yaml_files:
    try:
        doc = yaml.load(path.read_text(), Loader=_DuplicateKeyLoader)
    except yaml.YAMLError as exc:
        fail(f"{path.name}: YAML does not parse ({exc.__class__.__name__}: {exc})")
        continue

    if not isinstance(doc, dict) or "rules" not in doc:
        fail(f"{path.name}: missing top-level 'rules' key")
        continue

    for rule in doc["rules"]:
        missing = [f for f in REQUIRED if f not in rule]
        if missing:
            fail(f"{path.name}: rule missing required field(s): {', '.join(missing)}")
            continue

        rid = rule["id"]

        if rid in rule_ids:
            fail(f"{path.name}: duplicate rule id '{rid}' (also in {rule_ids[rid].name})")
        rule_ids[rid] = path

        if rid != path.stem:
            fail(f"{path.name}: rule id '{rid}' does not match filename stem '{path.stem}'")

        if rule["severity"] not in VALID_SEVERITY:
            fail(f"{rid}: severity '{rule['severity']}' not one of {sorted(VALID_SEVERITY)}")

        if set(rule["languages"]) not in VALID_LANGUAGES:
            fail(
                f"{rid}: expected languages to be exactly one of "
                f"{[sorted(s) for s in VALID_LANGUAGES]}, got {rule['languages']}"
            )
        if rule.get("mode") == "taint":
            for key in ("pattern-sources", "pattern-sinks"):
                if not rule.get(key):
                    fail(f"{rid}: taint rule is missing '{key}'")
            if not rule.get("pattern-sanitizers"):
                notes.append(f"{rid}: taint rule declares no pattern-sanitizers")
        else:
            if not any(k in rule for k in ("pattern", "patterns", "pattern-either", "pattern-regex")):
                fail(f"{rid}: search rule has no pattern/patterns/pattern-either/pattern-regex")

        if "metadata" not in rule or "cwe" not in rule.get("metadata", {}):
            notes.append(f"{rid}: no CWE in metadata")

if rule_ids and not failures:
    ok(f"{len(rule_ids)} rule(s) well-formed: {', '.join(sorted(rule_ids))}")
elif rule_ids:
    print(f"  ({len(rule_ids)} rule id(s) discovered)")


# ------------------------------------------------------------ 4-5. annotations
section("fixture annotations")

expected_counts: dict[str, dict[str, int]] = {}

fixture_paths = sorted(HERE.glob("*.java")) + sorted(HERE.glob("*.xml"))
for path in fixture_paths:
    annot = ANNOT_BY_SUFFIX.get(path.suffix)
    comment_prefix = COMMENT_PREFIX_BY_SUFFIX.get(path.suffix)
    if annot is None:
        continue

    lines = path.read_text().splitlines()
    counts = {"ruleid": 0, "ok": 0}
    seen_any = False

    for i, line in enumerate(lines):
        m = annot.search(line)
        if not m:
            continue
        seen_any = True
        kind, rid = m.group(1), m.group(2)
        counts[kind] = counts.get(kind, 0) + 1

        if rid not in rule_ids:
            fail(f"{path.name}:{i + 1}: annotation names unknown rule '{rid}'")

        # the annotated line must be followed by actual code
        nxt = next((l for l in lines[i + 1:] if l.strip()), "")
        if not nxt.strip() or nxt.strip().startswith(comment_prefix):
            fail(f"{path.name}:{i + 1}: annotation '{kind}: {rid}' is not above a code line")

    if not seen_any:
        fail(f"{path.name}: contains no ruleid/ok annotations")
    else:
        expected_counts[path.name] = counts

    if path.stem not in rule_ids:
        fail(f"{path.name}: no rule file matches this fixture's name")

for name, counts in expected_counts.items():
    ok(f"{name}: {counts['ruleid']} expected finding(s), {counts['ok']} expected clean line(s)")


# --------------------------------------------------------------- 6. javac
section("fixtures compile with javac")

java_files = sorted(HERE.glob("*.java"))
if java_files:
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run(
            ["javac", "-nowarn", "-proc:none", "-d", tmp, *[str(p) for p in java_files]],
            capture_output=True,
            text=True,
        )
    if proc.returncode == 0:
        ok(f"{len(java_files)} fixture file(s) compile cleanly")
    else:
        errs = [l for l in proc.stderr.splitlines() if "error:" in l]
        fail(f"javac rejected the fixtures ({len(errs)} error(s))")
        for line in errs[:10]:
            print(f"         {line}")


# ------------------------------------------------------------------ summary
print()
if notes:
    print("Notes (not failures):")
    for n in notes:
        print(f"  - {n}")
    print()

total_findings = sum(c["ruleid"] for c in expected_counts.values())
total_clean = sum(c["ok"] for c in expected_counts.values())
print(f"Ruleset: {len(rule_ids)} rules, {total_findings} positive and "
      f"{total_clean} negative fixture cases.")

if failures:
    print(f"\nFAILED: {len(failures)} problem(s).")
    sys.exit(1)

print("\nAll local checks passed.")
print("NOT verified here: whether the patterns actually match. That needs")
print("`semgrep --test --config . .`, which requires installing Semgrep.")
