"""Build the static report page from reports/latest.json.

    python -m agentwatch.site --repo-url https://github.com/<you>/agentwatch
    -> docs/index.html (self-contained; GitHub Pages can serve it from /docs)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "site" / "template.html"


def render(report: dict, fragment: bool = False) -> str:
    data = json.dumps(report, default=str).replace("</", "<\\/")
    body = TEMPLATE.read_text().replace("__AW_DATA__", data)
    if fragment:
        return body
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            "</head>\n<body>\n" + body + "\n</body>\n</html>\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="reports/latest.json")
    ap.add_argument("--out", default="docs/index.html")
    ap.add_argument("--repo-url", default="")
    ap.add_argument("--fragment", action="store_true", help="body only, no html/head wrapper")
    args = ap.parse_args()
    report = json.loads(Path(args.report).read_text())
    if args.repo_url:
        report["repo_url"] = args.repo_url
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(report, fragment=args.fragment))
    print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
