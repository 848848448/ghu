#!/usr/bin/env python3
"""Embed templates/index.html into worker.js as the PAGE template literal.

The Cloudflare Worker serves the frontend from a JS template literal
(`const PAGE = ` ... `;`). This script keeps that literal in sync with the
source file templates/index.html, escaping the three characters that are
special inside a backtick template literal: backslash, backtick, and `${`.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "templates" / "index.html"
WORKER = ROOT / "worker.js"

START = "const PAGE = `"
END = "`;"


def escape(html: str) -> str:
    # Order matters: escape backslashes first, then backticks, then ${.
    html = html.replace("\\", "\\\\")
    html = html.replace("`", "\\`")
    html = html.replace("${", "\\${")
    return html


def main() -> int:
    html = TEMPLATE.read_text(encoding="utf-8").rstrip("\n")
    worker = WORKER.read_text(encoding="utf-8")

    i = worker.rfind(START)
    if i < 0:
        print("Could not find PAGE start marker in worker.js", file=sys.stderr)
        return 1
    body_start = i + len(START)
    j = worker.find(END, body_start)
    if j < 0:
        print("Could not find PAGE end marker in worker.js", file=sys.stderr)
        return 1

    new_worker = worker[:body_start] + escape(html) + worker[j:]
    if new_worker == worker:
        print("worker.js already up to date.")
        return 0
    WORKER.write_text(new_worker, encoding="utf-8")
    print("Embedded templates/index.html into worker.js PAGE (%d chars)." % len(html))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
