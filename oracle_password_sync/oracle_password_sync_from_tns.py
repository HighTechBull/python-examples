#!/usr/bin/env python3
"""Synchronize an Oracle password across non-production TNS environments.

The script reads aliases from tnsnames.ora, excludes entries in the Production
section and aliases matching production safety rules, changes the connected
user's password with python-oracledb's native changepassword() API, or tests
logins without making changes, and prints a success/failure summary.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import oracledb
import pwinput

# Defense-in-depth filters. Entries beneath a "Production Databases" heading
# are excluded separately, but these rules protect against missing headings.
PRODUCTION_ALIAS_PATTERNS = (
    re.compile(r"^PROD", re.IGNORECASE),
    re.compile(r"(^|[_.$-])PROD([_.$-]|$)", re.IGNORECASE),
)

# These aliases appeared in the Production Databases section of the supplied
# tnsnames.ora but do not contain the word PROD.
EXPLICIT_PRODUCTION_ALIASES = {
    "",
}

@dataclass(frozen=True)
class TnsEnvironment:
    alias: str
    section: str


@dataclass(frozen=True)
class Result:
    environment: str
    succeeded: bool
    message: str


def default_tnsnames_path() -> Path:
    """Locate tnsnames.ora using TNS_ADMIN, then the current directory."""
    tns_admin = os.environ.get("TNS_ADMIN")
    if tns_admin:
        return Path(tns_admin).expanduser() / "tnsnames.ora"
    return Path.cwd() / "tnsnames.ora"


def normalize_heading(comment: str) -> Optional[str]:
    """Return a recognized section name from a tnsnames.ora comment line."""
    text = comment.lstrip("#").strip()
    if not text or set(text) <= {"#", "-", "=", "_"}:
        return None

    lowered = text.lower()
    section_names = {
        "production databases": "Production",
        "uat databases": "UAT",
        "load databases": "Load",
        "dev databases": "Development",
        "qa databases": "QA",
    }

    for marker, section in section_names.items():
        if marker in lowered:
            return section
    return None


def parse_tns_aliases(path: Path) -> list[TnsEnvironment]:
    """Read top-level aliases while preserving the surrounding section."""
    environments: list[TnsEnvironment] = []
    current_section = "Uncategorized"
    alias_pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(?:\(|$)")

    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text(encoding="cp1252").splitlines()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = normalize_heading(stripped)
            if heading:
                current_section = heading
            continue

        match = alias_pattern.match(line)
        if match:
            environments.append(
                TnsEnvironment(alias=match.group(1), section=current_section)
            )

    # Preserve file order while removing duplicate aliases case-insensitively.
    unique: list[TnsEnvironment] = []
    seen: set[str] = set()
    for environment in environments:
        key = environment.alias.upper()
        if key not in seen:
            seen.add(key)
            unique.append(environment)
    return unique


def is_production(environment: TnsEnvironment) -> bool:
    """Apply section, explicit-alias, and name-pattern production safeguards."""
    alias_upper = environment.alias.upper()
    if environment.section.lower() == "production":
        return True
    if alias_upper in EXPLICIT_PRODUCTION_ALIASES:
        return True
    return any(pattern.search(environment.alias) for pattern in PRODUCTION_ALIAS_PATTERNS)


def oracle_error_message(exc: oracledb.DatabaseError) -> str:
    """Return a readable Oracle error without exposing credentials."""
    if not exc.args:
        return str(exc)

    error = exc.args[0]
    code = getattr(error, "code", None)
    message = getattr(error, "message", str(error)).strip()

    # python-oracledb messages commonly already include ORA-nnnnn.
    if re.match(r"^(ORA|DPY)-\d+", message, re.IGNORECASE):
        return message
    if isinstance(code, int):
        return f"ORA-{code:05d}: {message}"
    return message


def process_environment(
    environment: str,
    username: str,
    current_password: str,
    new_password: Optional[str],
    config_dir: Path,
    test_only: bool,
) -> Result:
    """Connect to one environment and optionally change the password."""
    connection: Optional[oracledb.Connection] = None
    try:
        connection = oracledb.connect(
            user=username,
            password=current_password,
            dsn=environment,
            config_dir=str(config_dir),
        )

        if test_only:
            return Result(environment, True, "Login successful; password not changed")

        if new_password is None:
            return Result(environment, False, "New password was not provided")

        connection.changepassword(current_password, new_password)
        return Result(environment, True, "Password changed successfully")
    except oracledb.DatabaseError as exc:
        return Result(environment, False, oracle_error_message(exc))
    except Exception as exc:
        return Result(environment, False, f"Unexpected error: {exc}")
    finally:
        if connection is not None:
            try:
                connection.close()
            except oracledb.DatabaseError:
                pass


def print_environment_plan(
    included: list[TnsEnvironment], excluded: list[TnsEnvironment]
) -> None:
    print(f"\nNon-production environments selected: {len(included)}")
    for environment in included:
        print(f"  INCLUDE  {environment.alias} [{environment.section}]")

    print(f"\nProduction environments excluded: {len(excluded)}")
    for environment in excluded:
        print(f"  EXCLUDE  {environment.alias} [{environment.section}]")


def print_summary(results: list[Result]) -> None:
    print("\nPassword change summary")
    print("=" * 100)

    width = max([len("Environment"), *(len(item.environment) for item in results)])
    print(f"{'Environment':<{width}}  {'Status':<9}  Details")
    print(f"{'-' * width}  {'-' * 9}  {'-' * 60}")

    for result in results:
        status = "SUCCEEDED" if result.succeeded else "FAILED"
        print(f"{result.environment:<{width}}  {status:<9}  {result.message}")

    succeeded = sum(result.succeeded for result in results)
    failed = len(results) - succeeded
    print("=" * 100)
    print(f"Total: {len(results)} | Succeeded: {succeeded} | Failed: {failed}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Change an Oracle password across non-production aliases read "
            "from tnsnames.ora."
        )
    )
    parser.add_argument(
        "--tnsnames",
        type=Path,
        default=default_tnsnames_path(),
        help=(
            "Path to tnsnames.ora. Defaults to %%TNS_ADMIN%%/tnsnames.ora "
            "when TNS_ADMIN is set, otherwise ./tnsnames.ora."
        ),
    )
    parser.add_argument(
        "--oracle-client",
        type=Path,
        help=(
            "Optional Oracle Instant Client directory. "
            "If specified, Thick mode is used. "
            "Otherwise Thin mode is used."
        ),
    )
    parser.add_argument(
        "--test-only",
        action="store_true",
        help=(
            "Verify that the supplied username and current password can log "
            "in to every non-production database. No passwords are changed."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if args.oracle_client:
        try:
            oracledb.init_oracle_client(
                lib_dir=str(args.oracle_client)
            )
        except Exception as exc:
            print(
                f"ERROR: Failed to initialize Oracle Thick mode "
                f"using {args.oracle_client}: {exc}"
            )
            return 2

    print(
        f"Oracle mode: "
        f"{'Thin' if oracledb.is_thin_mode() else 'Thick'}"
    )
    
    tnsnames_path = args.tnsnames.expanduser().resolve()

    if not tnsnames_path.is_file():
        print(f"ERROR: tnsnames.ora was not found: {tnsnames_path}")
        return 2

    all_environments = parse_tns_aliases(tnsnames_path)
    if not all_environments:
        print(f"ERROR: No TNS aliases were found in {tnsnames_path}")
        return 2

    production = [item for item in all_environments if is_production(item)]
    non_production = [item for item in all_environments if not is_production(item)]

    if not non_production:
        print("ERROR: No non-production aliases remain after filtering.")
        return 2

    mode = "TEST ONLY" if args.test_only else "CHANGE PASSWORD"
    driver_mode = (
        "Thin" if oracledb.is_thin_mode() else "Thick"
    )

    print("Oracle Password Sync Tool")
    print(f"Mode: {mode}")
    print(f"Driver Mode: {driver_mode}")
    print(f"TNS file: {tnsnames_path}")    
    print("Passwords are masked and are not written to disk.")
    if args.test_only:
        print("Test-only mode will connect to each database without changing it.")
    print_environment_plan(non_production, production)

    required_confirmation = "TEST" if args.test_only else "CHANGE"
    confirmation = input(
        f"\nType {required_confirmation} to continue: "
    ).strip()
    if confirmation != required_confirmation:
        print("Cancelled. No database passwords were changed.")
        return 0

    username = input("Oracle username: ").strip()
    current_password = pwinput.pwinput("Current password: ", mask="*")
    new_password: Optional[str] = None

    if not username:
        print("ERROR: Username cannot be empty.")
        return 2
    if not current_password:
        print("ERROR: Current password cannot be empty.")
        return 2

    if not args.test_only:
        new_password = pwinput.pwinput("New password: ", mask="*")
        confirmed_password = pwinput.pwinput("Confirm new password: ", mask="*")

        if not new_password:
            print("ERROR: New password cannot be empty.")
            return 2
        if new_password != confirmed_password:
            print("ERROR: The new passwords do not match. No databases were changed.")
            return 2
        if current_password == new_password:
            print("ERROR: The new password must differ from the current password.")
            return 2

    results: list[Result] = []
    action = "Testing" if args.test_only else "Updating"
    for environment in non_production:
        print(f"{action} {environment.alias} ...", end=" ", flush=True)
        result = process_environment(
            environment.alias,
            username,
            current_password,
            new_password,
            tnsnames_path.parent,
            args.test_only,
        )
        results.append(result)
        print("SUCCEEDED" if result.succeeded else "FAILED")

    print_summary(results)
    return 1 if any(not result.succeeded for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
