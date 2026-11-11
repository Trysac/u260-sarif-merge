"""Tests for sarif_merge."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from sarif_merge import (
    SarifError,
    compare_baseline,
    load_sarif,
    merge,
    result_key,
)


def make_result(
    *,
    rule_id: str,
    uri: str = "src/app.py",
    uri_base_id: str = "",
    start_line: int | None = 10,
    message_text: str = "SQL injection",
    partial_fingerprint: str | None = None,
    locations: bool = True,
    rule_index: int | None = None,
    include_artifacts: bool = False,
    artifact_index: int | None = None,
) -> dict:
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": message_text},
    }
    if locations:
        art_loc: dict[str, Any] = {"uri": uri}
        if uri_base_id:
            art_loc["uriBaseId"] = uri_base_id
        if artifact_index is not None:
            art_loc["index"] = artifact_index
        region = {}
        if start_line is not None:
            region["startLine"] = start_line
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": art_loc, "region": region}}
        ]
    if partial_fingerprint:
        result["partialFingerprints"] = {"primaryLocationLineHash": partial_fingerprint}
    if rule_index is not None:
        result["ruleIndex"] = rule_index
    if include_artifacts:
        result["artifacts"] = [{"location": {"uri": "extra"}}]
    return result


def make_run(
    *,
    tool_name: str,
    version: str = "",
    rules: list[dict] | None = None,
    results: list[dict] | None = None,
    include_artifacts: bool = False,
) -> dict:
    driver: dict[str, Any] = {"name": tool_name}
    if version:
        # decide semanticVersion vs version: if version starts with 'sem:', use semanticVersion
        if version.startswith("sem:"):
            driver["semanticVersion"] = version[4:]
        else:
            driver["version"] = version
    if rules is not None:
        driver["rules"] = rules
    run: dict[str, Any] = {"tool": {"driver": driver}}
    if results is not None:
        run["results"] = results
    if include_artifacts:
        run["artifacts"] = [{"location": {"uri": "run-artifact"}}]
    return run


def make_log(*runs: dict) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": list(runs),
    }


def get_driver(run: dict) -> dict:
    return run["tool"]["driver"]


# --- result_key tests ---


def test_result_key_uses_fingerprint_when_present():
    run = make_run(tool_name="t", rules=[{"id": "r1"}])
    result = make_result(rule_id="r1", partial_fingerprint="abc:1", locations=False)
    key = result_key(result, run)
    expected = hashlib.sha256(b"r1|fp|abc:1").hexdigest()
    assert key == expected


def test_result_key_fallback_normalizes_uri():
    run = make_run(tool_name="t", rules=[{"id": "r1"}])
    result1 = make_result(rule_id="r1", uri="./src/app.py")
    result2 = make_result(rule_id="r1", uri="src\\app.py")
    result3 = make_result(rule_id="r1", uri="src/app.py")
    key1 = result_key(result1, run)
    key2 = result_key(result2, run)
    key3 = result_key(result3, run)
    assert key1 == key2 == key3


def test_result_key_empty_parts_when_no_locations():
    run = make_run(tool_name="t", rules=[{"id": "r1"}])
    result = make_result(rule_id="r1", locations=False, message_text="")
    key = result_key(result, run)
    expected = hashlib.sha256(b"r1||||").hexdigest()
    assert key == expected


# --- load_sarif tests ---


def test_load_sarif_valid():
    log = make_log(make_run(tool_name="semgrep"))
    loaded = load_sarif(json.dumps(log))
    assert loaded == log


def test_load_sarif_invalid_json():
    with pytest.raises(SarifError) as exc_info:
        load_sarif("not json")
    assert exc_info.value.code == "invalid_json"


def test_load_sarif_unsupported_version():
    log = {"version": "2.0.0", "runs": []}
    with pytest.raises(SarifError) as exc_info:
        load_sarif(json.dumps(log))
    assert exc_info.value.code == "unsupported_version"


def test_load_sarif_missing_version():
    log = {"runs": []}
    with pytest.raises(SarifError) as exc_info:
        load_sarif(json.dumps(log))
    assert exc_info.value.code == "invalid_sarif"


def test_load_sarif_input_too_large():
    text = "x" * 100
    with pytest.raises(SarifError) as exc_info:
        load_sarif(text, max_bytes=50)
    assert exc_info.value.code == "input_too_large"


def test_load_sarif_too_many_results():
    run = make_run(tool_name="t", results=[make_result(rule_id="r") for _ in range(5)])
    log = make_log(run)
    with pytest.raises(SarifError) as exc_info:
        load_sarif(json.dumps(log), max_results=4)
    assert exc_info.value.code == "too_many_results"


def test_load_sarif_missing_tool_driver_name():
    run = {"tool": {"driver": {"name": ""}}, "results": []}
    log = make_log(run)
    with pytest.raises(SarifError) as exc_info:
        load_sarif(json.dumps(log))
    assert exc_info.value.code == "invalid_sarif"


def test_load_sarif_non_dict_top_level():
    with pytest.raises(SarifError) as exc_info:
        load_sarif(json.dumps([1, 2]))
    assert exc_info.value.code == "invalid_sarif"


def test_load_sarif_runs_not_list():
    log = {"version": "2.1.0", "runs": "not a list"}
    with pytest.raises(SarifError) as exc_info:
        load_sarif(json.dumps(log))
    assert exc_info.value.code == "invalid_sarif"


# --- merge tests ---


def test_merge_deduplicates_same_result():
    log_a = make_log(make_run(tool_name="semgrep", results=[make_result(rule_id="py.sqli")]))
    log_b = make_log(make_run(tool_name="semgrep", results=[make_result(rule_id="py.sqli")]))
    merged = merge([log_a, log_b])
    assert len(merged["runs"]) == 1
    run = merged["runs"][0]
    assert len(run["results"]) == 1
    assert run["properties"]["sarifMerge"] == {"inputResults": 2, "duplicates": 1}


def test_merge_uri_normalization_dedupe():
    log = make_log(
        make_run(
            tool_name="semgrep",
            rules=[{"id": "r"}],
            results=[
                make_result(rule_id="r", uri="./src/app.py"),
                make_result(rule_id="r", uri="src\\app.py"),
                make_result(rule_id="r", uri="src/app.py"),
            ],
        )
    )
    merged = merge([log])
    assert len(merged["runs"]) == 1
    assert len(merged["runs"][0]["results"]) == 1


def test_merge_sorts_runs_by_name():
    log_semgrep = make_log(make_run(tool_name="semgrep", results=[make_result(rule_id="s")]))
    log_bandit = make_log(make_run(tool_name="bandit", results=[make_result(rule_id="b")]))
    merged = merge([log_semgrep, log_bandit])
    names = [run["tool"]["driver"]["name"] for run in merged["runs"]]
    assert names == ["bandit", "semgrep"]


def test_merge_reindexes_rules():
    log_a = make_log(
        make_run(
            tool_name="tool",
            rules=[{"id": "r1"}],
            results=[make_result(rule_id="r1", rule_index=0)],
        )
    )
    log_b = make_log(
        make_run(
            tool_name="tool",
            rules=[{"id": "r2"}, {"id": "r1"}],
            results=[
                make_result(rule_id="r2", rule_index=0),
            ],
        )
    )
    merged = merge([log_a, log_b])
    run = merged["runs"][0]
    merged_rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert merged_rules == ["r1", "r2"]
    result = run["results"][1]  # order: first result from A, then from B
    assert result["ruleId"] == "r2"
    assert result["ruleIndex"] == 1


def test_merge_fingerprint_wins_over_location():
    log = make_log(
        make_run(
            tool_name="tool",
            rules=[{"id": "r"}],
            results=[
                make_result(rule_id="r", partial_fingerprint="fp1", start_line=10),
                make_result(rule_id="r", partial_fingerprint="fp1", start_line=20),
            ],
        )
    )
    merged = merge([log])
    assert len(merged["runs"][0]["results"]) == 1


def test_merge_different_versions_separate_runs():
    log1 = make_log(
        make_run(tool_name="tool", version="sem:1.0", results=[make_result(rule_id="r")])
    )
    log2 = make_log(
        make_run(tool_name="tool", version="sem:2.0", results=[make_result(rule_id="r")])
    )
    merged = merge([log1, log2])
    assert len(merged["runs"]) == 2
    versions = [
        run["tool"]["driver"].get("semanticVersion", run["tool"]["driver"].get("version", ""))
        for run in merged["runs"]
    ]
    assert versions == ["1.0", "2.0"]


def test_merge_empty_runs_list():
    log = {"version": "2.1.0", "runs": []}
    merged = merge([log])
    assert merged["runs"] == []


def test_merge_empty_input_sequence():
    merged = merge([])
    assert merged == {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }


# Edge cases
def test_merge_result_without_locations():
    log = make_log(
        make_run(
            tool_name="tool",
            rules=[{"id": "r"}],
            results=[make_result(rule_id="r", locations=False)],
        )
    )
    merged = merge([log])
    assert len(merged["runs"][0]["results"]) == 1


def test_merge_rule_id_from_rule_object():
    result = {
        "rule": {"id": "r"},
        "message": {"text": "msg"},
        "locations": [],
    }
    run = make_run(tool_name="tool", rules=[{"id": "r"}], results=[result])
    log = make_log(run)
    merged = merge([log])
    assert merged["runs"][0]["results"][0]["ruleId"] == "r"


def test_merge_rule_id_from_rule_index():
    result = {
        "ruleIndex": 0,
        "message": {"text": "msg"},
        "locations": [],
    }
    run = make_run(tool_name="tool", rules=[{"id": "r"}], results=[result])
    log = make_log(run)
    merged = merge([log])
    assert merged["runs"][0]["results"][0]["ruleId"] == "r"


def test_merge_strips_nested_artifact_location_indexes():
    result: dict[str, Any] = {
        "ruleId": "r",
        "message": {"text": "msg"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py", "index": 0},
                    "region": {"startLine": 10},
                }
            }
        ],
        "relatedLocations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/other.py", "index": 0},
                    "region": {"startLine": 3},
                }
            }
        ],
        "artifacts": [{"location": {"uri": "extra"}}],
    }
    run = make_run(tool_name="tool", rules=[{"id": "r"}], results=[result], include_artifacts=True)
    log = make_log(run)
    merged = merge([log])
    merged_run = merged["runs"][0]
    assert "artifacts" not in merged_run
    merged_result = merged_run["results"][0]
    assert "artifacts" not in merged_result
    assert "index" not in merged_result["locations"][0]["physicalLocation"]["artifactLocation"]
    related = merged_result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]
    assert "index" not in related


def test_merge_missing_rule_id_raises():
    result = {"message": {"text": "msg"}}
    run = make_run(tool_name="tool", rules=[{"id": "r"}], results=[result])
    log = make_log(run)
    with pytest.raises(SarifError) as exc_info:
        merge([log])
    assert exc_info.value.code == "invalid_sarif"


def test_merge_rules_first_definition_wins():
    log1 = make_log(
        make_run(tool_name="tool", rules=[{"id": "r1", "description": "first"}], results=[])
    )
    log2 = make_log(
        make_run(tool_name="tool", rules=[{"id": "r1", "description": "second"}], results=[])
    )
    merged = merge([log1, log2])
    rules = merged["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["description"] == "first"


# --- compare_baseline tests ---


def test_compare_baseline_marks_states():
    current = make_log(
        make_run(
            tool_name="tool",
            rules=[{"id": "A"}, {"id": "B"}],
            results=[
                make_result(rule_id="A", uri="a.py"),
                make_result(rule_id="B", uri="b.py"),
            ],
        )
    )
    baseline = make_log(
        make_run(
            tool_name="tool",
            rules=[{"id": "B"}, {"id": "C"}],
            results=[
                make_result(rule_id="B", uri="b.py"),
                make_result(rule_id="C", uri="c.py"),
            ],
        )
    )
    compared = compare_baseline(current, baseline)
    run = compared["runs"][0]
    results = run["results"]
    assert len(results) == 3
    assert results[0]["ruleId"] == "A" and results[0]["baselineState"] == "new"
    assert results[1]["ruleId"] == "B" and results[1]["baselineState"] == "unchanged"
    assert results[2]["ruleId"] == "C" and results[2]["baselineState"] == "absent"
    # The absent result's rule definition must be appended and its index reindexed.
    assert [r["id"] for r in get_driver(run)["rules"]] == ["A", "B", "C"]
    assert results[2]["ruleIndex"] == 2
    assert results[0]["ruleIndex"] == 0
    assert results[1]["ruleIndex"] == 1


def test_compare_baseline_all_new_when_no_baseline_tool():
    current = make_log(make_run(tool_name="tool1", results=[make_result(rule_id="r")]))
    baseline = make_log(make_run(tool_name="tool2", results=[make_result(rule_id="r")]))
    compared = compare_baseline(current, baseline)
    assert compared["runs"][0]["results"][0]["baselineState"] == "new"


def test_compare_baseline_tool_without_baseline_run():
    current = make_log(make_run(tool_name="tool", results=[make_result(rule_id="r")]))
    baseline = make_log(make_run(tool_name="other", results=[make_result(rule_id="r")]))
    compared = compare_baseline(current, baseline)
    assert compared["runs"][0]["results"][0]["baselineState"] == "new"


# CLI tests (require tmp_path)
def test_cli_merge(tmp_path):
    (tmp_path / "a.sarif").write_text(
        json.dumps(make_log(make_run(tool_name="semgrep", results=[make_result(rule_id="r")])))
    )
    (tmp_path / "b.sarif").write_text(
        json.dumps(make_log(make_run(tool_name="semgrep", results=[make_result(rule_id="r")])))
    )
    output = tmp_path / "out.sarif"
    from sarif_merge.__main__ import main

    rc = main(
        ["merge", str(tmp_path / "a.sarif"), str(tmp_path / "b.sarif"), "--output", str(output)]
    )
    assert rc == 0
    assert output.exists()
    merged = json.loads(output.read_text())
    assert len(merged["runs"]) == 1
    assert len(merged["runs"][0]["results"]) == 1


def test_cli_baseline_fail_on_new(tmp_path):
    current = make_log(
        make_run(tool_name="tool", rules=[{"id": "new"}], results=[make_result(rule_id="new")])
    )
    baseline = make_log(
        make_run(tool_name="tool", rules=[{"id": "old"}], results=[make_result(rule_id="old")])
    )
    (tmp_path / "cur.sarif").write_text(json.dumps(current))
    (tmp_path / "base.sarif").write_text(json.dumps(baseline))
    output = tmp_path / "o.sarif"
    from sarif_merge.__main__ import main

    rc = main(
        [
            "baseline",
            str(tmp_path / "cur.sarif"),
            str(tmp_path / "base.sarif"),
            "--output",
            str(output),
            "--fail-on-new",
        ]
    )
    assert rc == 1
    assert output.exists()
    compared = json.loads(output.read_text())
    assert compared["runs"][0]["results"][0]["baselineState"] == "new"


def test_cli_baseline_no_new_returns_zero(tmp_path):
    current = make_log(
        make_run(tool_name="tool", rules=[{"id": "r"}], results=[make_result(rule_id="r")])
    )
    baseline = make_log(
        make_run(tool_name="tool", rules=[{"id": "r"}], results=[make_result(rule_id="r")])
    )
    (tmp_path / "cur.sarif").write_text(json.dumps(current))
    (tmp_path / "base.sarif").write_text(json.dumps(baseline))
    output = tmp_path / "o.sarif"
    from sarif_merge.__main__ import main

    rc = main(
        [
            "baseline",
            str(tmp_path / "cur.sarif"),
            str(tmp_path / "base.sarif"),
            "--output",
            str(output),
            "--fail-on-new",
        ]
    )
    assert rc == 0


def test_cli_missing_file_returns_2(tmp_path):
    from sarif_merge.__main__ import main

    rc = main(["merge", str(tmp_path / "missing.sarif"), "--output", str(tmp_path / "out.sarif")])
    assert rc == 2


def test_cli_invalid_json_returns_2(tmp_path):
    p = tmp_path / "bad.sarif"
    p.write_text("not json")
    from sarif_merge.__main__ import main

    rc = main(["merge", str(p), "--output", str(tmp_path / "out.sarif")])
    assert rc == 2


def test_cli_unknown_subcommand_returns_2():
    from sarif_merge.__main__ import main

    rc = main(["unknown"])
    assert rc == 2
