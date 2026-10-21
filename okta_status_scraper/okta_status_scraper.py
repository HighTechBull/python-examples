
#!/usr/bin/env python3
"""
Scrape Okta's status page HTML and ALWAYS return JSON, even if the page
is login-gated or parsing fails.

Usage:
    python okta_status_scraper.py
    python okta_status_scraper.py --url https://status.okta.com/ --out okta_status.json
    python okta_status_scraper.py --debug

Dependencies:
    pip install requests beautifulsoup4
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

DEFAULT_URL = "https://status.okta.com/"

STATUS_WORDS = {
    "Operational": "operational",
    "Degraded Performance": "degraded_performance",
    "Service Degradation": "degraded_performance",
    "Partial Outage": "partial_outage",
    "Major Outage": "major_outage",
    "Service Disruption": "major_outage",
    "Under Maintenance": "under_maintenance",
    "Maintenance": "under_maintenance",
    "System Operational": "operational",
    "All Systems Operational": "operational",
}

LOGIN_HINTS = [
    "Sign In As Administrator",
    "Sign in",
    "Okta – Sign In",
    "login.okta.com",
]

def fetch_html(url: str, timeout: int = 20, debug: bool = False):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
        )
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if debug:
            print(f"[DEBUG] HTTP {resp.status_code} | final URL: {resp.url}", file=sys.stderr)
        return resp.status_code, resp.url, resp.text
    except Exception as e:
        if debug:
            print(f"[DEBUG] fetch_html error: {e}", file=sys.stderr)
        return None, url, None

def normalize_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def extract_overall_status(soup: BeautifulSoup):
    candidates = []
    for selector in ["h1", "h2", "h3", "div", "span", "[class*=status]", "[class*=overall]"]:
        for el in soup.select(selector):
            txt = normalize_whitespace(el.get_text(" ", strip=True))
            if txt:
                candidates.append(txt)

    for txt in candidates:
        for key in STATUS_WORDS:
            if key.lower() in txt.lower():
                return {"text": key, "normalized": STATUS_WORDS.get(key, key.lower().replace(" ", "_"))}

    page_txt = normalize_whitespace(soup.get_text(" ", strip=True))
    for key in STATUS_WORDS:
        if re.search(re.escape(key), page_txt, flags=re.IGNORECASE):
            return {"text": key, "normalized": STATUS_WORDS.get(key, key.lower().replace(" ", "_"))}

    return {"text": "Unknown", "normalized": "unknown"}

def extract_components(soup: BeautifulSoup):
    page_text = soup.get_text("\n", strip=True)
    lines = [normalize_whitespace(line) for line in page_text.split("\n")]
    lines = [line for line in lines if line and len(line.split()) >= 2]

    status_regex = re.compile(
        r"\b("
        r"Operational|Degraded Performance|Service Degradation|Partial Outage|Major Outage|"
        r"Service Disruption|Under Maintenance|Maintenance"
        r")\b",
        flags=re.IGNORECASE,
    )

    components = []
    seen = set()

    for line in lines:
        m = status_regex.search(line)
        if not m:
            continue
        status_text = m.group(1)
        status_norm = STATUS_WORDS.get(status_text, status_text.lower().replace(" ", "_"))

        name = normalize_whitespace(line[: m.start()]).rstrip(" -–:").strip()
        if not name or len(name) < 2:
            continue

        key = (name.lower(), status_norm)
        if key in seen:
            continue
        seen.add(key)

        components.append({
            "name": name,
            "status": status_norm,
            "status_text": status_text,
        })

    return components

def make_summary(url: str, status_code, final_url: str, html: str, debug: bool = False) -> dict:
    diagnostics = {
        "http_status": status_code,
        "final_url": final_url,
        "login_detected": False,
        "parseable": False,
        "notes": [],
    }

    if not html or status_code is None:
        diagnostics["notes"].append("No HTML retrieved.")
        return {
            "page_url": url,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": {"text": "Unknown", "normalized": "unknown"},
            "components": [],
            "diagnostics": diagnostics,
        }

    if any(hint.lower() in html.lower() for hint in LOGIN_HINTS):
        diagnostics["login_detected"] = True
        diagnostics["notes"].append("Login page detected; returning empty components.")

    soup = BeautifulSoup(html, "html.parser")
    overall = extract_overall_status(soup)
    components = extract_components(soup)
    diagnostics["parseable"] = bool(components) or (overall["normalized"] != "unknown")

    return {
        "page_url": url,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "components": components,
        "diagnostics": diagnostics,
    }

def main():
    parser = argparse.ArgumentParser(description="Okta status HTML → JSON (login-safe)")
    parser.add_argument("--url", default=DEFAULT_URL, help="Status page URL")
    parser.add_argument("--out", default="", help="Output file path (default: stdout)")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    status_code, final_url, html = fetch_html(args.url, timeout=args.timeout, debug=args.debug)
    summary = make_summary(args.url, status_code, final_url, html, debug=args.debug)

    output = json.dumps(summary, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        print(output)

if __name__ == "__main__":
    main()
