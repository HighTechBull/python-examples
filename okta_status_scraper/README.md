# Okta Status Scraper

Fetch an Okta status page and extract its overall status and component statuses from the page's HTML. The scraper emits a JSON summary to standard output or to a file, including diagnostics when the page cannot be fetched or appears to be login-gated.

## Requirements

- Python 3
- The packages listed in [`requirements.txt`](requirements.txt)
- Network access to the status page

Install the dependencies with:

```sh
python -m pip install -r requirements.txt
```

## Usage

Run from this directory to scrape the default URL, `https://status.okta.com/`:

```sh
python okta_status_scraper.py
```

Specify a URL, save the JSON to a file, or enable debug output:

```sh
python okta_status_scraper.py --url https://status.okta.com/ --out okta_status.json
python okta_status_scraper.py --timeout 30 --debug
```

### Options

- `--url URL`: Status page URL. Defaults to `https://status.okta.com/`.
- `--out PATH`: Write JSON to this file instead of standard output.
- `--timeout SECONDS`: HTTP request timeout. Defaults to 20 seconds.
- `--debug`: Print request details and fetch errors to standard error.

## JSON output

The summary contains:

- `page_url` and `checked_at` (an ISO 8601 UTC timestamp).
- `overall_status`, with the text found on the page and a normalized value such as `operational`, `partial_outage`, or `unknown`.
- `components`, a list of component names and their normalized and original status text.
- `diagnostics`, including the HTTP status, final URL after redirects, whether login-page text was detected, whether status data was parsed, and any notes.

If the request fails, the script still emits a JSON summary with an unknown overall status, an empty component list, and a diagnostic note. HTML parsing is heuristic; changes to the status page's markup or wording can affect the extracted results.