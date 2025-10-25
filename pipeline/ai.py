import json
import os
from typing import Dict, List, Optional, Tuple

import requests


DEEPSEEK_ENDPOINT = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"


def _truncate(text: str, max_chars: int = 6000) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 50] + "\n...[truncated]"


def _build_prompt(item: Dict) -> List[Dict[str, str]]:
    system = (
        "You are a senior malware analyst. Provide precise, actionable findings, cite specific behaviors, "
        "and avoid speculation. If uncertain, say so."
    )
    # Build compact user content
    def fmt_list(name: str, arr: List[str], limit: int = 30) -> str:
        if not arr:
            return f"{name}: []"
        use = arr[:limit]
        return name + ":\n- " + "\n- ".join(use)

    path = item.get("rel_path") or item.get("path") or "(unknown)"
    hashes = item.get("hashes", {})
    imports = item.get("imports", [])
    strings = item.get("strings", [])
    iocs = item.get("iocs", {})
    reasons = item.get("reasons", [])
    pseudocode_snippets = item.get("pseudocode", [])

    pseudo_joined = "\n\n".join([_truncate(s, 2000) for s in pseudocode_snippets])

    user = f"""
Target file: {path}
Hashes: md5={hashes.get('md5')} sha1={hashes.get('sha1')} sha256={hashes.get('sha256')}
File type: {item.get('file_type')}
Size: {item.get('size')} bytes
Suspicious reasons: {', '.join(reasons) if reasons else '(none)'}

Top imports (subset):\n- """ + "\n- ".join(imports[:40]) + "\n\n" + \
        fmt_list("IOC URLs", iocs.get("urls", []), 20) + "\n" + \
        fmt_list("IOC IPs", iocs.get("ips", []), 20) + "\n" + \
        fmt_list("IOC Domains", iocs.get("domains", []), 20) + "\n\n" + \
        "Pseudocode snippets (truncated):\n" + pseudo_joined + "\n\n" + \
        "Please analyze and return: (1) concise executive summary; (2) likely behaviors; (3) risk level (Low/Medium/High/Critical); " + \
        "(4) concrete IOCs; (5) MITRE ATT&CK techniques; (6) recommended actions; (7) a short JSON block with fields: summary, risk, behaviors, iocs, mitre, actions."

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": _truncate(user, 12000)},
    ]


def analyze_with_deepseek(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not set")
    endpoint = endpoint or DEEPSEEK_ENDPOINT
    model = model or DEEPSEEK_MODEL

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    results: List[Dict] = []
    for item in items:
        payload = {
            "model": model,
            "messages": _build_prompt(item),
            "temperature": 0.2,
            "max_tokens": 1200,
        }
        resp = requests.post(endpoint, headers=headers, data=json.dumps(payload), timeout=60)
        if resp.status_code >= 300:
            results.append({"error": f"HTTP {resp.status_code}", "detail": resp.text, "item": item})
            continue
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        results.append({"item": item, "analysis": content})
    return results


