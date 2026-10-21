# Oracle Password Sync

This script changes one Oracle user's password across the non-production database aliases in a `tnsnames.ora` file. It can also test the current credentials without changing any passwords.

## Requirements

- Python 3.9 or later
- The Python packages listed in [`requirements.txt`](requirements.txt)
- A `tnsnames.ora` file containing the aliases to process

Install the Python dependencies with:

```powershell
py -m pip install -r requirements.txt
```

The script uses Oracle Thin mode by default and does not require Oracle Instant Client. To use Thick mode, install Oracle Instant Client separately and provide its directory with `--oracle-client`.

## Usage

Run commands from this directory:

```powershell
py oracle_password_sync_from_tns.py [--tnsnames PATH] [--oracle-client DIRECTORY] [--test-only]
```

Test the current username and password against every selected alias without changing passwords:

```powershell
py oracle_password_sync_from_tns.py --test-only
```

Change the password across the selected aliases:

```powershell
py oracle_password_sync_from_tns.py
```

Use a specific TNS file or Oracle Instant Client directory:

```powershell
py oracle_password_sync_from_tns.py --tnsnames C:\path\to\tnsnames.ora
py oracle_password_sync_from_tns.py --oracle-client C:\path\to\instantclient
```

### Options

- `--tnsnames PATH`: TNS configuration file. Defaults to `%TNS_ADMIN%\tnsnames.ora` when `TNS_ADMIN` is set, otherwise `tnsnames.ora` in the current directory.
- `--oracle-client DIRECTORY`: Initialize Oracle Thick mode using the specified Instant Client directory. Without this option, Thin mode is used.
- `--test-only`: Attempt logins only; do not change passwords.

## Selection and safety

The script reads aliases from the TNS file and displays the included and excluded environments before asking for confirmation. Aliases in a section identified by a `Production Databases` comment are excluded. It also excludes aliases beginning with `PROD` or containing `PROD` as a token separated by `_`, `.`, `$`, or `-` (case-insensitive).

After reviewing the plan, type `TEST` or `CHANGE` to continue. Credentials are entered interactively; password prompts are masked. In change mode, the new password must be entered twice and must differ from the current password.

Aliases are processed one at a time. A failure partway through a change run does not roll back password changes that already succeeded, so review the final per-alias summary.

## Exit status

- `0`: All database operations succeeded, or the run was cancelled.
- `1`: One or more database operations failed.
- `2`: A setup or input error prevented processing, such as a missing TNS file or invalid Oracle client initialization.