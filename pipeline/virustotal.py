import json
import os
import time
from typing import Dict, List, Optional

import requests


VT_API_URL = "https://www.virustotal.com/api/v3"


def _build_headers(api_key: str) -> Dict[str, str]:
    return {
        "x-apikey": api_key,
        "accept": "application/json",
    }


def vt_get_file_report(sha256: str, api_key: str, session: Optional[requests.Session] = None) -> Optional[Dict]:
    sess = session or requests.Session()
    url = f"{VT_API_URL}/files/{sha256}"
    try:
        resp = sess.get(url, headers=_build_headers(api_key), timeout=20)
        if resp.status_code == 404:
            return {"found": False, "sha256": sha256}
        resp.raise_for_status()
        data = resp.json()
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        results = attr.get("last_analysis_results", {})
        tags = attr.get("tags", [])
        reputation = attr.get("reputation")
        harmless = int(stats.get("harmless", 0))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        timeout = int(stats.get("timeout", 0))
        return {
            "found": True,
            "sha256": sha256,
            "stats": {
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "timeout": timeout,
            },
            "reputation": reputation,
            "tags": tags,
            "results": results,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    except Exception:
        return None


def query_virustotal_for_items(static_items: List[Dict], out_dir: str) -> Dict[str, Dict]:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {}

    vt_dir = os.path.join(out_dir, "vt")
    os.makedirs(vt_dir, exist_ok=True)

    max_lookups_env = os.getenv("VT_MAX_LOOKUPS", "50")
    try:
        max_lookups = max(0, int(max_lookups_env))
    except Exception:
        max_lookups = 50

    results: Dict[str, Dict] = {}
    session = requests.Session()

    # Respect simple rate limits: default free tier is very limited. Add small delay between calls.
    delay_s_env = os.getenv("VT_DELAY_SEC", "1.0")
    try:
        delay_s = max(0.0, float(delay_s_env))
    except Exception:
        delay_s = 1.0

    count = 0
    for item in static_items:
        if max_lookups and count >= max_lookups:
            break
        sha256 = item.get("sha256")
        if not sha256:
            continue

        out_path = os.path.join(vt_dir, f"{sha256}.json")
        cached: Optional[Dict] = None
        if os.path.isfile(out_path):
            try:
                with open(out_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
            except Exception:
                cached = None
        if cached is not None:
            results[sha256] = cached
            count += 1
            continue

        data = vt_get_file_report(sha256, api_key, session=session)
        if data is not None:
            results[sha256] = data
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
        # Delay between requests to avoid hitting strict rate limits
        if delay_s > 0:
            time.sleep(delay_s)
        count += 1

    return results


