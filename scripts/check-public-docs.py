#!/usr/bin/env python3
"""Offline checks for the deliberately authored public Markdown and diagrams."""

import html
import re
import sys
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def outside_fences(text):
    return re.sub(r"^```[^\n]*\n.*?^```\s*$", "", text, flags=re.M | re.S)


def anchors(text):
    result, counts = set(), {}
    for title in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", outside_fences(text), re.M):
        title = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", title)
        title = html.unescape(re.sub(r"<[^>]+>", "", title)).lower()
        slug = "".join(c for c in title if c in "-_ " or unicodedata.category(c)[0] in "LN")
        slug = slug.replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        result.add(slug if count == 0 else f"{slug}-{count}")
    result.update(re.findall(r'<a\s+(?:name|id)=["\']([^"\']+)', text))
    return result


def check():
    docs = sorted(set(ROOT.glob("*.md")) | set((ROOT / "Documentation").rglob("*.md"))
                  | set((ROOT / "lab-examples").rglob("*.md")))
    errors = []
    for path in docs:
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            errors.append(f"{relative}: public document must not be a symlink")
            continue
        text = path.read_text()
        if re.search(r"/(?:Users/[^/$\s]+|private/tmp)/|bgpls-private|file://", text):
            errors.append(f"{relative}: private/local-only path in public documentation")
        if len(re.findall(r"^```", text, re.M)) % 2:
            errors.append(f"{relative}: unclosed code fence")
        for code in re.findall(r"^```swift\s*\n(.*?)^```", text, re.M | re.S):
            if re.search(r"\b(?:try|as)!|[\w)\]]!(?!=)", code):
                errors.append(f"{relative}: forced operation in Swift example")
        for match in re.finditer(r"!?\[[^\n]*?\]\((<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)", outside_fences(text)):
            raw = match.group(1).strip("<>")
            link = urllib.parse.urlsplit(raw)
            if link.scheme in ("https", "http", "mailto"):
                continue
            if link.scheme or link.netloc or link.path.startswith("/"):
                errors.append(f"{relative}: unsupported/absolute local link {raw}")
                continue
            target = (path.parent / urllib.parse.unquote(link.path)).resolve() if link.path else path
            if not target.is_relative_to(ROOT):
                errors.append(f"{relative}: link escapes public tree: {raw}")
            elif not target.exists():
                errors.append(f"{relative}: missing link target: {raw}")
            elif link.fragment and target.suffix.lower() == ".md":
                if urllib.parse.unquote(link.fragment) not in anchors(target.read_text()):
                    errors.append(f"{relative}: missing heading anchor: {raw}")
    diagrams = sorted((ROOT / "Documentation").rglob("*.drawio"))
    images = sorted((ROOT / "Documentation").rglob("*.svg"))
    for path in diagrams + images:
        try:
            data = path.read_text()
            ET.fromstring(data)
            if re.search(r"/(?:Users/|private/tmp/)|bgpls-private|file://", data):
                errors.append(f"{path.relative_to(ROOT)}: local/private diagram metadata")
        except (ET.ParseError, UnicodeError) as error:
            errors.append(f"{path.relative_to(ROOT)}: invalid XML: {error}")
    if not docs or not diagrams or not images:
        errors.append("Expected public Markdown, editable draw.io, and SVG documentation")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Public documentation: {len(docs)} Markdown files, {len(diagrams)} draw.io files, {len(images)} SVG files checked")
    return 0


if __name__ == "__main__":
    sys.exit(check())
