# Python Examples

This repository contains small, standalone Python tools. Each subproject has its own dependencies and usage instructions.

## Subprojects

### [Oracle Password Sync](oracle_password_sync/README.md)

Tests Oracle credentials or changes one user's password across non-production database aliases read from `tnsnames.ora`. It displays the selected and excluded aliases and requires confirmation before connecting. See the [script](oracle_password_sync/oracle_password_sync_from_tns.py) and its README for installation and usage details.

### [Veracode Report Parser](veracode_report_parser/README.md)

Parses a Veracode Detailed Report XML file and generates JSON and Markdown summaries for unmitigated Static Analysis findings and SCA component vulnerabilities. See the [script](veracode_report_parser/veracode_report_parser.py) and its README for usage details.

### [Okta Status Scraper](okta_status_scraper/README.md)

Fetches an Okta status page and emits a JSON summary of its overall and component statuses, with diagnostics for fetch and parsing results. See the [script](okta_status_scraper/okta_status_scraper.py) and its README for usage details.