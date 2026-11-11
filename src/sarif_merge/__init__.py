"""Merge SARIF 2.1.0 logs from multiple scanners into one de-duplicated log with baseline states."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any, Literal

__all__ = [
    "SarifError",
    "compare_baseline",
    "load_sarif",
    "merge",
    "result_key",
]

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

SarifErrorCode = Literal[
    "invalid_json",
    "unsupported_version",
    "invalid_sarif",
    "input_too_large",
    "too_many_results",
]


class SarifError(ValueError):
    """Base error for sarif_merge with a machine-readable code."""

    def __init__(self, code: SarifErrorCode, message: str = "") -> None:
        super().__init__(message)
        self.code = code


def _get_rule_id(result: Mapping[str, Any], run: Mapping[str, Any]) -> str:
    """Extract a stable ruleId from a SARIF result."""
    raw_rule_id = result.get("ruleId")
    if isinstance(raw_rule_id, str):
        return raw_rule_id
    rule = result.get("rule")
    if isinstance(rule, Mapping):
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            return rule_id
    rule_index = result.get("ruleIndex")
    if isinstance(rule_index, int):
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, Mapping) else None
        rules = driver.get("rules") if isinstance(driver, Mapping) else None
        if isinstance(rules, list) and 0 <= rule_index < len(rules):
            indexed_rule = rules[rule_index]
            if isinstance(indexed_rule, Mapping):
                indexed_rule_id = indexed_rule.get("id")
                if isinstance(indexed_rule_id, str):
                    return indexed_rule_id
    return ""


def _normalize_uri(uri: str) -> str:
    """Normalise a file URI for fingerprinting: backslashes to '/', strip leading './'."""
    uri = uri.replace("\\", "/")
    if uri.startswith("./"):
        uri = uri[2:]
    return uri


def result_key(result: Mapping[str, Any], run: Mapping[str, Any]) -> str:
    """Compute a stable SHA-256 key for a SARIF result.

    If ``partialFingerprints.primaryLocationLineHash`` is present, only that fingerprint
    and the rule ID are used. Otherwise a fallback based on rule ID, URI, URI base ID,
    start line and message text is used.
    """
    rule_id = _get_rule_id(result, run)
    partial = result.get("partialFingerprints", {})
    if isinstance(partial, Mapping) and "primaryLocationLineHash" in partial:
        fp = partial["primaryLocationLineHash"]
        string_to_hash = f"{rule_id}|fp|{fp}"
    else:
        # fallback
        locations = result.get("locations", [])
        first_loc = locations[0] if locations else {}
        physical = first_loc.get("physicalLocation", {}) if isinstance(first_loc, Mapping) else {}
        art_loc = physical.get("artifactLocation", {}) if isinstance(physical, Mapping) else {}
        uri_base_id = art_loc.get("uriBaseId", "") or ""
        uri = art_loc.get("uri", "") or ""
        uri = _normalize_uri(uri)
        region = physical.get("region", {}) if isinstance(physical, Mapping) else {}
        start_line = region.get("startLine", "")
        start_line_str = str(start_line) if start_line != "" else ""
        message = result.get("message", {})
        message_text = message.get("text", "") if isinstance(message, Mapping) else ""
        string_to_hash = f"{rule_id}|{uri_base_id}|{uri}|{start_line_str}|{message_text}"
    return hashlib.sha256(string_to_hash.encode("utf-8")).hexdigest()


def _strip_artifact_indexes(node: Any) -> None:
    """Recursively pop ``index`` from every ``artifactLocation`` object under *node*.

    Run-level ``artifacts`` arrays are dropped when merging, so any surviving
    ``artifactLocation.index`` would dangle (SARIF 2.1.0 requires ``run.artifacts``
    whenever an index is present). This walks results, relatedLocations, codeFlows,
    stacks, fixes/artifactChanges, attachments and similar nested structures.
    """
    if isinstance(node, dict):
        artifact_location = node.get("artifactLocation")
        if isinstance(artifact_location, dict):
            artifact_location.pop("index", None)
        for value in node.values():
            _strip_artifact_indexes(value)
    elif isinstance(node, list):
        for item in node:
            _strip_artifact_indexes(item)


def _reconcile_rules(
    current_run: dict[str, Any],
    baseline_run: dict[str, Any],
    appended_rule_ids: list[str],
) -> None:
    """Append baseline rule definitions for absent results and reindex all results.

    Absent results come from the baseline run, whose rules array may differ from the
    current one; their definitions are appended (first definition of an id wins) and
    every ``ruleIndex`` is recomputed against the reconciled array. Results whose
    ``ruleId`` has no definition lose their ``ruleIndex``.
    """
    driver = current_run.get("tool", {}).get("driver", {})
    if not isinstance(driver, dict):
        return
    rules = driver.get("rules")
    if not isinstance(rules, list):
        rules = []
    seen: set[str] = set()
    for rule in rules:
        if isinstance(rule, dict):
            rule_id = rule.get("id")
            if isinstance(rule_id, str):
                seen.add(rule_id)
    baseline_driver = baseline_run.get("tool", {}).get("driver", {})
    baseline_rules = baseline_driver.get("rules", {}) if isinstance(baseline_driver, dict) else {}
    baseline_by_id: dict[str, Any] = {}
    if isinstance(baseline_rules, list):
        for rule in baseline_rules:
            if isinstance(rule, dict):
                rule_id = rule.get("id")
                if isinstance(rule_id, str) and rule_id not in baseline_by_id:
                    baseline_by_id[rule_id] = rule
    for rule_id in appended_rule_ids:
        if isinstance(rule_id, str) and rule_id not in seen and rule_id in baseline_by_id:
            seen.add(rule_id)
            rules.append(copy.deepcopy(baseline_by_id[rule_id]))
    driver["rules"] = rules

    index_by_id: dict[str, int] = {}
    for index, rule in enumerate(rules):
        if isinstance(rule, dict):
            rule_id = rule.get("id")
            if isinstance(rule_id, str) and rule_id not in index_by_id:
                index_by_id[rule_id] = index
    results = current_run.get("results", [])
    if not isinstance(results, list):
        return
    for result in results:
        if not isinstance(result, dict):
            continue
        rule_id = result.get("ruleId")
        if isinstance(rule_id, str) and rule_id in index_by_id:
            result["ruleIndex"] = index_by_id[rule_id]
        else:
            result.pop("ruleIndex", None)


def load_sarif(
    text: str, *, max_bytes: int = 52_428_800, max_results: int = 100_000
) -> dict[str, Any]:
    """Parse and validate a SARIF 2.1.0 log from JSON text.

    Raises:
        SarifError with the appropriate code on any validation failure.
    """
    if len(text.encode("utf-8")) > max_bytes:
        raise SarifError("input_too_large", f"SARIF text exceeds {max_bytes} bytes")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SarifError("invalid_json", str(exc)) from exc
    except RecursionError as exc:
        raise SarifError("invalid_json", "recursion limit exceeded while parsing JSON") from exc

    if not isinstance(data, dict):
        raise SarifError("invalid_sarif", "top-level SARIF must be an object")
    version = data.get("version")
    if version != "2.1.0":
        if version is None:
            raise SarifError("invalid_sarif", "SARIF log missing 'version'")
        raise SarifError("unsupported_version", f"unsupported SARIF version: {version!r}")
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise SarifError("invalid_sarif", "SARIF 'runs' must be a list")

    total_results = 0
    for run in runs:
        if not isinstance(run, dict):
            raise SarifError("invalid_sarif", "each run must be an object")
        tool = run.get("tool")
        if not isinstance(tool, dict):
            raise SarifError("invalid_sarif", "run 'tool' must be an object")
        driver = tool.get("driver")
        if not isinstance(driver, dict):
            raise SarifError("invalid_sarif", "tool 'driver' must be an object")
        name = driver.get("name")
        if not isinstance(name, str) or not name:
            raise SarifError("invalid_sarif", "tool.driver.name must be a non-empty string")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise SarifError("invalid_sarif", "run 'results' must be a list")
        total_results += len(results)
        if total_results > max_results:
            raise SarifError("too_many_results", f"total results exceed {max_results}")
    return data


def merge(logs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple SARIF logs into one.

    Runs are grouped by tool driver name and version. Rules are merged per group in
    first-seen order; results are de-duplicated using :func:`result_key`.
    """
    if not logs:
        # Return an empty SARIF log
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [],
        }

    groups: dict[tuple[str, str], list[tuple[dict[str, Any], list[dict[str, Any]]]]] = {}
    for log in logs:
        if not isinstance(log, dict):
            raise SarifError("invalid_sarif", "log must be a dict")
        runs = log.get("runs", [])
        if not isinstance(runs, list):
            raise SarifError("invalid_sarif", "log 'runs' must be a list")
        for run in runs:
            if not isinstance(run, dict):
                raise SarifError("invalid_sarif", "run must be a dict")
            driver = run.get("tool", {}).get("driver", {})
            name = driver.get("name", "")
            if not isinstance(name, str) or not name:
                raise SarifError("invalid_sarif", "tool.driver.name is required")
            version = driver.get("semanticVersion") or driver.get("version") or ""
            if not isinstance(version, str):
                version = str(version)
            key = (name, version)
            results = run.get("results", [])
            if not isinstance(results, list):
                raise SarifError("invalid_sarif", "run 'results' must be a list")
            groups.setdefault(key, []).append((run, results))

    merged_runs: list[tuple[tuple[str, str], dict[str, Any]]] = []
    for key, run_results_pairs in groups.items():
        total_input_results = sum(len(results) for _, results in run_results_pairs)
        # Collect all rules in first-seen order across runs, first definition wins by id.
        seen_rule_ids: set[str] = set()
        merged_rules: list[dict[str, Any]] = []
        for run, _ in run_results_pairs:
            driver = run["tool"]["driver"]
            rules = driver.get("rules", [])
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rule_id = rule.get("id")
                if isinstance(rule_id, str) and rule_id not in seen_rule_ids:
                    seen_rule_ids.add(rule_id)
                    merged_rules.append(copy.deepcopy(rule))

        merged_results: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        duplicates = 0
        for run, results in run_results_pairs:
            for result in results:
                if not isinstance(result, dict):
                    raise SarifError("invalid_sarif", "result must be an object")
                rule_id = _get_rule_id(result, run)
                if not rule_id:
                    raise SarifError("invalid_sarif", "cannot determine ruleId for result")
                result_hash = result_key(result, run)
                if result_hash in seen_keys:
                    duplicates += 1
                    continue
                seen_keys.add(result_hash)
                new_result = copy.deepcopy(result)
                # Set ruleId and recompute ruleIndex against the merged rules array.
                new_result["ruleId"] = rule_id
                for index, merged_rule in enumerate(merged_rules):
                    if merged_rule.get("id") == rule_id:
                        new_result["ruleIndex"] = index
                        break
                else:
                    # No rule definition survived the merge: drop the stale index.
                    new_result.pop("ruleIndex", None)
                # Strip artifacts arrays and every artifactLocation.index (nested too)
                new_result.pop("artifacts", None)
                _strip_artifact_indexes(new_result)
                merged_results.append(new_result)

        # Build merged run from the first run in group, replacing rules and results.
        first_run = run_results_pairs[0][0]
        merged_run = copy.deepcopy(first_run)
        merged_run.pop("artifacts", None)  # drop run-level artifacts
        merged_run["tool"]["driver"]["rules"] = merged_rules
        merged_run["results"] = merged_results
        # Merge properties, adding sarifMerge last
        original_props = merged_run.get("properties", {})
        if not isinstance(original_props, dict):
            original_props = {}
        new_props = copy.deepcopy(original_props)
        new_props["sarifMerge"] = {
            "inputResults": total_input_results,
            "duplicates": duplicates,
        }
        merged_run["properties"] = new_props
        merged_runs.append((key, merged_run))

    # Sort runs by (name, version)
    merged_runs.sort(key=lambda item: item[0])
    output_runs = [run for _, run in merged_runs]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": output_runs,
    }


def compare_baseline(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Mark each result in ``current`` as 'new' or 'unchanged' relative to ``baseline``.

    Results only in ``baseline`` are appended with baselineState 'absent'.
    Both logs are merged first via :func:`merge`.
    """
    merged_current = merge([current])
    merged_baseline = merge([baseline])

    baseline_runs_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for run in merged_baseline["runs"]:
        driver = run["tool"]["driver"]
        name = driver["name"]
        version = driver.get("semanticVersion") or driver.get("version") or ""
        baseline_runs_by_key[(name, version)] = run

    for current_run in merged_current["runs"]:
        driver = current_run["tool"]["driver"]
        name = driver["name"]
        version = driver.get("semanticVersion") or driver.get("version") or ""
        baseline_run = baseline_runs_by_key.get((name, version))

        current_results = current_run.get("results", [])
        if not isinstance(current_results, list):
            current_results = []
        # Compute keys for current results (before modifications)
        current_keys: set[str] = set()
        for res in current_results:
            current_keys.add(result_key(res, current_run))

        if baseline_run is None:
            # all new
            for res in current_results:
                res["baselineState"] = "new"
        else:
            baseline_results = baseline_run.get("results", [])
            baseline_keys: set[str] = set()
            for res in baseline_results:
                baseline_keys.add(result_key(res, baseline_run))
            for res in current_results:
                if result_key(res, current_run) in baseline_keys:
                    res["baselineState"] = "unchanged"
                else:
                    res["baselineState"] = "new"
            # Append baseline-only results as absent
            appended_rule_ids: list[str] = []
            for res in baseline_results:
                if result_key(res, baseline_run) not in current_keys:
                    new_res = copy.deepcopy(res)
                    new_res["baselineState"] = "absent"
                    current_run["results"].append(new_res)
                    appended_rule_ids.append(new_res.get("ruleId", ""))
            if appended_rule_ids:
                _reconcile_rules(current_run, baseline_run, appended_rule_ids)

    return merged_current
