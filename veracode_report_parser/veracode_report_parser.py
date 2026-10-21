#!/usr/bin/env python3
"""
Parse a Veracode Detailed Report XML file and create separate reports for:
  1. Static Analysis findings that do not have a mitigation
  2. Software Composition Analysis component vulnerabilities

Outputs created in the current working directory:
  static_analysis_summary.json
  static_analysis_summary.md
  sca_summary.json
  sca_summary.md

Usage:
  python veracode_report_parser.py detailed_report.xml

Optional:
  python veracode_report_parser.py detailed_report.xml --output-dir reports
"""

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


VERACODE_NAMESPACE = "https://www.veracode.com/schema/reports/export/1.0"
NS = {"v": VERACODE_NAMESPACE}


SEVERITY_NAMES = {
    "5": "Very High",
    "4": "High",
    "3": "Medium",
    "2": "Low",
    "1": "Very Low",
    "0": "Informational",
    "unknown": "Unknown",
}


def severity_name(severity):
    return SEVERITY_NAMES.get(str(severity), str(severity))


def severity_sort_key(severity):
    text = str(severity)
    return int(text) if text.isdigit() else -1


def local_name(tag):
    """Return XML local tag name without namespace."""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def all_descendants_by_name(root, name):
    """Find descendants by local tag name, regardless of namespace."""
    return [element for element in root.iter() if local_name(element.tag) == name]


def attr_any(element, names, default=""):
    """Return the first non-empty attribute from a list of possible names."""
    for name in names:
        value = element.attrib.get(name)
        if value not in (None, ""):
            return value
    return default


def has_child_named(element, child_name):
    return any(local_name(child.tag) == child_name for child in list(element))


def clean_text(value):
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def markdown_escape(value):
    text = clean_text(value)
    return text.replace("|", "\\|")


def parse_static_flaws(root):
    """
    Parse static analysis flaws that do not have a mitigation.

    Veracode static flaws are represented by <flaw> nodes. SCA vulnerabilities
    are represented by <vulnerability> nodes and are handled separately.
    """
    findings = defaultdict(list)
    seen_issue_ids = set()

    for flaw in all_descendants_by_name(root, "flaw"):
        mitigation_status = attr_any(flaw, ["mitigation_status"], "").strip().lower()

        # The request is to include application-code flaws that do not have a mitigation.
        # In Veracode XML, unmitigated findings commonly have mitigation_status="none".
        if mitigation_status not in ("", "none"):
            continue

        issue_id = attr_any(flaw, ["issueid", "issue_id"], "")
        if issue_id and issue_id in seen_issue_ids:
            continue
        if issue_id:
            seen_issue_ids.add(issue_id)

        severity = attr_any(flaw, ["severity"], "unknown")

        findings[severity].append({
            "issue_id": issue_id,
            "severity": severity,
            "severity_name": severity_name(severity),
            "category": attr_any(flaw, ["categoryname", "category_name"], ""),
            "cwe": attr_any(flaw, ["cweid", "cwe_id"], ""),
            "module": attr_any(flaw, ["module"], ""),
            "source_file": attr_any(flaw, ["sourcefile", "source_file"], ""),
            "source_path": attr_any(flaw, ["sourcefilepath", "source_path"], ""),
            "line": attr_any(flaw, ["line"], ""),
            "scope": attr_any(flaw, ["scope"], ""),
            "function_prototype": attr_any(flaw, ["functionprototype", "function_prototype"], ""),
            "type": attr_any(flaw, ["type"], ""),
            "remediation_status": attr_any(flaw, ["remediation_status"], ""),
            "remediation_effort": attr_any(flaw, ["remediationeffort", "remediation_effort"], ""),
            "description": clean_text(attr_any(flaw, ["description"], "")),
        })

    return findings


def component_has_vulnerabilities(component):
    raw_count = attr_any(component, ["vulnerabilities", "vulnerability_count", "vuln_count"], "")
    if raw_count:
        try:
            return int(raw_count) > 0
        except ValueError:
            pass
    return any(local_name(child.tag) == "vulnerability" for child in component.iter())


def parse_sca(root):
    """
    Parse Software Composition Analysis vulnerabilities and group by severity.

    The Veracode Detailed Report has varied slightly across versions, so this
    parser uses local tag names and multiple attribute aliases.
    """
    findings = defaultdict(list)
    seen = set()

    for component in all_descendants_by_name(root, "component"):
        if not component_has_vulnerabilities(component):
            continue

        component_name = attr_any(
            component,
            ["file_name", "filename", "name", "component_name", "library"],
            "Unknown Component",
        )
        version = attr_any(component, ["version", "library_version"], "")
        vendor = attr_any(component, ["vendor", "vendor_name"], "")
        file_path = attr_any(component, ["file_path", "filepath", "path"], "")
        sha1 = attr_any(component, ["sha1", "sha1sum", "hash"], "")
        license_name = attr_any(component, ["license", "licenses"], "")

        vulnerability_nodes = [
            child for child in component.iter()
            if local_name(child.tag) == "vulnerability"
        ]

        for vulnerability in vulnerability_nodes:
            cve = attr_any(
                vulnerability,
                ["cve", "cve_id", "cveid", "name"],
                "",
            )
            severity = attr_any(
                vulnerability,
                ["severity", "severity_id", "severity_level"],
                "unknown",
            )
            severity_desc = attr_any(
                vulnerability,
                ["severity_desc", "severity_description"],
                severity_name(severity),
            )
            cvss = attr_any(
                vulnerability,
                ["cvss_score", "cvss", "cvss3_score", "score"],
                "",
            )
            cwe = attr_any(vulnerability, ["cwe", "cwe_id", "cweid"], "")
            summary = clean_text(attr_any(vulnerability, ["summary", "title"], ""))
            description = clean_text(attr_any(vulnerability, ["description", "details"], ""))
            mitigation = attr_any(vulnerability, ["mitigation", "mitigated"], "")

            dedupe_key = "|".join([
                component_name,
                version,
                cve,
                summary,
                cvss,
            ])
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            findings[severity].append({
                "component": component_name,
                "version": version,
                "vendor": vendor,
                "file_path": file_path,
                "sha1": sha1,
                "license": license_name,
                "cve": cve,
                "cwe": cwe,
                "cvss": cvss,
                "severity": severity,
                "severity_name": severity_desc or severity_name(severity),
                "summary": summary,
                "description": description,
                "mitigation": mitigation,
            })

    return findings


def to_plain_dict(findings):
    return {
        severity: findings[severity]
        for severity in sorted(findings.keys(), key=severity_sort_key, reverse=True)
    }


def severity_counts(findings):
    return {
        severity: len(findings[severity])
        for severity in sorted(findings.keys(), key=severity_sort_key, reverse=True)
    }


def write_json_report(path, findings, report_type):
    report = {
        "report_type": report_type,
        "total_findings": sum(len(items) for items in findings.values()),
        "severity_counts": severity_counts(findings),
        "findings": to_plain_dict(findings),
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_static_markdown(path, findings):
    lines = []
    total = sum(len(items) for items in findings.values())

    lines.append("# Static Analysis Findings")
    lines.append("")
    lines.append(f"Total unmitigated findings: **{total}**")
    lines.append("")

    if total == 0:
        lines.append("No unmitigated static analysis findings were found.")
        lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return

    for severity in sorted(findings.keys(), key=severity_sort_key, reverse=True):
        items = findings[severity]
        lines.append(f"## Severity {severity} ({severity_name(severity)})")
        lines.append("")
        lines.append(f"Count: **{len(items)}**")
        lines.append("")
        lines.append("| Issue ID | Category | CWE | Module | Source File | Line | Remediation |")
        lines.append("|---|---|---|---|---|---|---|")

        for flaw in items:
            lines.append(
                "| {issue_id} | {category} | {cwe} | {module} | {source_file} | {line} | {remediation} |".format(
                    issue_id=markdown_escape(flaw.get("issue_id", "")),
                    category=markdown_escape(flaw.get("category", "")),
                    cwe=markdown_escape(flaw.get("cwe", "")),
                    module=markdown_escape(flaw.get("module", "")),
                    source_file=markdown_escape(flaw.get("source_file", "")),
                    line=markdown_escape(flaw.get("line", "")),
                    remediation=markdown_escape(flaw.get("remediation_status", "")),
                )
            )

        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_sca_markdown(path, findings):
    lines = []
    total = sum(len(items) for items in findings.values())

    lines.append("# Software Composition Analysis Findings")
    lines.append("")
    lines.append(f"Total component vulnerabilities: **{total}**")
    lines.append("")

    if total == 0:
        lines.append("No vulnerable SCA components were found by this parser.")
        lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return

    for severity in sorted(findings.keys(), key=severity_sort_key, reverse=True):
        items = findings[severity]
        lines.append(f"## Severity {severity} ({severity_name(severity)})")
        lines.append("")
        lines.append(f"Count: **{len(items)}**")
        lines.append("")
        lines.append("| Component | Version | CVE | CVSS | CWE | Summary |")
        lines.append("|---|---|---|---|---|---|")

        for vulnerability in items:
            lines.append(
                "| {component} | {version} | {cve} | {cvss} | {cwe} | {summary} |".format(
                    component=markdown_escape(vulnerability.get("component", "")),
                    version=markdown_escape(vulnerability.get("version", "")),
                    cve=markdown_escape(vulnerability.get("cve", "")),
                    cvss=markdown_escape(vulnerability.get("cvss", "")),
                    cwe=markdown_escape(vulnerability.get("cwe", "")),
                    summary=markdown_escape(vulnerability.get("summary", "")),
                )
            )

        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def print_summary(title, findings):
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)

    total = sum(len(items) for items in findings.values())
    for severity in sorted(findings.keys(), key=severity_sort_key, reverse=True):
        print(f"Severity {severity} ({severity_name(severity)}): {len(findings[severity])}")

    print(f"Total: {total}")


def main():
    parser = argparse.ArgumentParser(description="Parse a Veracode Detailed Report XML file.")
    parser.add_argument("xml_file", help="Path to the Veracode detailed_report.xml file")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory where output reports should be written. Default: current directory",
    )

    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    tree = ET.parse(args.xml_file)
    root = tree.getroot()

    static_findings = parse_static_flaws(root)
    sca_findings = parse_sca(root)

    static_json = output_dir / "static_analysis_summary.json"
    static_md = output_dir / "static_analysis_summary.md"
    sca_json = output_dir / "sca_summary.json"
    sca_md = output_dir / "sca_summary.md"

    write_json_report(static_json, static_findings, "static_analysis")
    write_static_markdown(static_md, static_findings)
    write_json_report(sca_json, sca_findings, "software_composition_analysis")
    write_sca_markdown(sca_md, sca_findings)

    print_summary("UNMITIGATED STATIC ANALYSIS FINDINGS", static_findings)
    print_summary("SOFTWARE COMPOSITION ANALYSIS FINDINGS", sca_findings)

    print()
    print("Generated files:")
    print(f"  {static_json}")
    print(f"  {static_md}")
    print(f"  {sca_json}")
    print(f"  {sca_md}")


if __name__ == "__main__":
    main()
