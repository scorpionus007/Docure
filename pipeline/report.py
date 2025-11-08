import json
import os
from typing import Dict, List


def _md_escape(s: str) -> str:
    return s.replace("<", "&lt;").replace(">", "&gt;")


def generate_ai_report(aggregated: Dict, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    report_json = os.path.join(out_dir, "report.json")
    report_md = os.path.join(out_dir, "report.md")

    with open(report_json, "w", encoding="utf-8") as f:
        json.dump(aggregated, f, indent=2, ensure_ascii=False)

    # Markdown
    lines: List[str] = []
    lines.append("## Executive Summary")
    flagged = aggregated.get("flagged_for_ai", [])
    if not flagged:
        lines.append("No high-suspicion files detected by heuristics.")
    else:
        lines.append(f"{len(flagged)} file(s) flagged for AI review.")

    lines.append("\n## Technical Findings")
    for item in aggregated.get("static", []):
        lines.append(f"- `{item.get('rel_path')}` — type: {item.get('file_type')} — sha256: `{item.get('sha256')}` — score: {item.get('suspicion_score', 0)}")

    # VirusTotal summary
    vt = aggregated.get("virustotal") or {}
    if vt:
        lines.append("\n## VirusTotal")
        for sha, entry in vt.items():
            if not isinstance(entry, dict):
                continue
            found = entry.get("found")
            if found:
                stats = entry.get("stats", {})
                mal = stats.get("malicious", 0)
                susp = stats.get("suspicious", 0)
                und = stats.get("undetected", 0)
                url = entry.get("permalink", f"https://www.virustotal.com/gui/file/{sha}")
                lines.append(f"- `{sha}` — VT: malicious={mal} suspicious={susp} undetected={und} — [{_md_escape(url)}]({_md_escape(url)})")
            elif found is False:
                lines.append(f"- `{sha}` — VT: no record found")

    lines.append("\n## AI Analyses")
    for r in aggregated.get("ai_results", []):
        item = r.get("item", {})
        content = r.get("analysis", "")
        lines.append(f"### `{item.get('rel_path', 'unknown')}`")
        if content:
            lines.append(_md_escape(content))
        else:
            lines.append("(No AI content)")

    with open(report_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


