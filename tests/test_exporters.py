"""Unit tests for Table, JSON, and SARIF report exporters."""

import json

from lh_hid_provisioner.exporters import export_json, export_sarif, export_table
from lh_hid_provisioner.models import LintFinding, LintReport, Severity


def make_sample_report(has_issues: bool = True) -> LintReport:
    if not has_issues:
        return LintReport(file_path="clean_script.txt", findings=[])

    findings = [
        LintFinding(
            rule_id="SEC-001",
            rule_name="Destructive Filesystem Command",
            severity=Severity.CRITICAL,
            line_number=10,
            message="Destructive recursive deletion.",
            code_snippet="STRING rm -rf /",
            suggestion="Remove destructive command.",
        ),
        LintFinding(
            rule_id="SYN-004",
            rule_name="Unsafe Unquoted Shell Variable",
            severity=Severity.MEDIUM,
            line_number=15,
            message="Unquoted variable $HOST.",
            code_snippet="STRING echo $HOST",
            suggestion='Wrap variable in double quotes: "$HOST".',
        ),
    ]
    return LintReport(file_path="test_script.txt", findings=findings)


def test_export_table_clean() -> None:
    report = make_sample_report(has_issues=False)
    table_str = export_table(report)
    assert "No issues found" in table_str
    assert "PASS" in table_str


def test_export_table_with_findings() -> None:
    report = make_sample_report(has_issues=True)
    table_str = export_table(report)
    assert "SEC-001" in table_str
    assert "CRITICAL" in table_str
    assert "SYN-004" in table_str
    assert "Total Issues" in table_str


def test_export_json() -> None:
    report = make_sample_report(has_issues=True)
    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["file"] == "test_script.txt"
    assert data["passed"] is False
    assert data["summary"]["total_issues"] == 2
    assert data["summary"]["critical"] == 1
    assert data["summary"]["medium"] == 1
    assert len(data["findings"]) == 2
    assert data["findings"][0]["rule_id"] == "SEC-001"


def test_export_sarif() -> None:
    report = make_sample_report(has_issues=True)
    sarif_str = export_sarif(report)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in data["$schema"]
    assert len(data["runs"]) == 1

    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-hid-provisioner"
    assert len(driver["rules"]) == 2

    results = data["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "SEC-001"
    assert results[0]["level"] == "error"
    res0_loc = results[0]["locations"][0]["physicalLocation"]
    assert res0_loc["artifactLocation"]["uri"] == "test_script.txt"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 10

    assert results[1]["ruleId"] == "SYN-004"
    assert results[1]["level"] == "warning"
