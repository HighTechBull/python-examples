# Veracode Report Parser

Parse a Veracode Detailed Report XML file into separate summaries for unmitigated Static Analysis findings and Software Composition Analysis (SCA) component vulnerabilities.

## Requirements

- Python 3
- A Veracode Detailed Report XML file

The script uses only Python's standard library; no third-party packages need to be installed. [`requirements.txt`](requirements.txt) is included for dependency tracking.

## Usage

Run from this directory:

```sh
python veracode_report_parser.py path/to/detailed_report.xml
```

Choose a directory for the generated reports with `--output-dir`:

```sh
python veracode_report_parser.py path/to/detailed_report.xml --output-dir reports
```

The output directory is created if it does not already exist. Relative input and output paths are resolved from the current working directory.

## Generated reports

The parser creates four files in the output directory:

- `static_analysis_summary.json`: unmitigated Static Analysis findings grouped by severity, with a total and severity counts.
- `static_analysis_summary.md`: a readable table of those findings, including issue ID, category, CWE, module, source file, line, and remediation status.
- `sca_summary.json`: SCA vulnerabilities grouped by severity, with a total and severity counts.
- `sca_summary.md`: a readable table of SCA vulnerabilities, including component, version, CVE, CVSS, CWE, and summary.

## Parsing behavior

- Static Analysis entries are read from `<flaw>` elements. Entries whose `mitigation_status` is empty or `none` are included. Repeated non-empty issue IDs are included only once.
- SCA entries are read from `<vulnerability>` elements within components that report vulnerabilities. Repeated entries with the same component, version, CVE, summary, and CVSS are included only once.
- XML elements are matched by their local tag names, so namespace prefixes do not need to match a particular spelling.
- Findings are grouped by their severity value. Numeric severities are ordered descending, with non-numeric values after them.

The parser prints a count by severity and a total for each report type, followed by the paths of the generated files.