import json
import os
from typing import Dict, List

from .static_analysis import (
    identify_candidates,
    compute_hashes_and_metadata,
    extract_strings,
    collect_iocs,
    suspicion_score,
    write_static_artifact,
)
from .ai import analyze_with_deepseek
from .report import generate_ai_report
from .virustotal import query_virustotal_for_items
from .unpacking import unpack_file, is_upx_available


def _load_manifest(manifest_path: str) -> Dict:
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    # If this is the small pointer manifest from cli_ingest (contains manifest_path),
    # load the real file manifest so we have the files list.
    if "files" not in manifest and isinstance(manifest.get("manifest_path"), str):
        real_path = manifest.get("manifest_path")
        try:
            with open(real_path, "r", encoding="utf-8") as rf:
                real = json.load(rf)
            # Ensure rootfs points correctly for downstream functions
            if "root" not in real:
                # Prefer explicit rootfs from outer manifest
                if manifest.get("rootfs"):
                    real["root"] = manifest["rootfs"]
            return real
        except Exception:
            pass
    return manifest


def analyze_image(
    manifest_path: str,
    out_dir: str,
    use_deepseek: bool = True,
    max_files: int = 200,
    max_size_mb: int = 50,
    verbose: bool = False,
) -> Dict:
    os.makedirs(out_dir, exist_ok=True)

    manifest = _load_manifest(manifest_path)
    rootfs = manifest.get("root") or manifest.get("rootfs") or manifest.get("sandbox")
    if not rootfs:
        raise RuntimeError("Manifest missing rootfs path")

    # 1) Candidate selection
    candidates = identify_candidates(manifest, rootfs, max_files=max_files, max_size_mb=max_size_mb)
    if verbose:
        print(f"[pipeline] Candidates selected: {len(candidates)}")
        debug_dir = os.path.join(out_dir, "debug")
        os.makedirs(debug_dir, exist_ok=True)
        with open(os.path.join(debug_dir, "candidates.txt"), "w", encoding="utf-8") as f:
            for c in candidates:
                f.write(c + "\n")

    # 2) Static metadata per candidate
    static_dir = os.path.join(out_dir, "static")
    unpack_dir = os.path.join(out_dir, "unpacked")
    os.makedirs(unpack_dir, exist_ok=True)
    static_items: List[Dict] = []
    unpacked_files: Dict[str, str] = {}  # Map original path to unpacked path

    for rel in candidates:
        meta = compute_hashes_and_metadata(rootfs, rel)
        strings = extract_strings(meta["abs_path"])[:200]
        iocs = collect_iocs(strings)
        item = {
            **meta,
            "strings": strings,
            "iocs": iocs,
        }
        write_static_artifact(os.path.join(static_dir, meta["sha256"] + ".json"), item)
        static_items.append(item)

        # 2.5) Attempt unpacking if file is packed
        if meta.get("is_packed") and meta.get("packer_type"):
            packer_type = meta.get("packer_type")
            if verbose:
                print(f"[pipeline] Attempting to unpack {rel} (packer: {packer_type})")

            unpack_result = unpack_file(
                meta["abs_path"],
                packer_type=packer_type,
                output_dir=unpack_dir
            )

            if unpack_result.get("success") and unpack_result.get("unpacked_path"):
                unpacked_path = unpack_result["unpacked_path"]
                unpacked_files[meta["abs_path"]] = unpacked_path
                item["unpacked"] = {
                    "success": True,
                    "unpacked_path": unpacked_path,
                    "packer_type": packer_type,
                }
                if verbose:
                    print(f"[pipeline] Successfully unpacked to: {unpacked_path}")
            else:
                item["unpacked"] = {
                    "success": False,
                    "error": unpack_result.get("error"),
                    "packer_type": packer_type,
                }
                if verbose:
                    print(f"[pipeline] Unpacking failed: {unpack_result.get('error')}")

    # 3) VirusTotal by hash (optional via VT_API_KEY)
    vt_results = query_virustotal_for_items(static_items, out_dir)

    # 4) Suspicion scoring integrating imports/strings
    flagged_for_ai: List[Dict] = []
    for it in static_items:
        imports: List[str] = []
        if it.get("pe_imports"):
            imports = [str(x) for x in it.get("pe_imports", [])][:100]
        elif it.get("elf_imports"):
            imports = [str(x) for x in it.get("elf_imports", [])][:100]
        pseudocode_snippets: List[str] = []
        score, reasons = suspicion_score(it, it.get("strings", []), imports)
        it["imports"] = imports
        it["pseudocode"] = pseudocode_snippets
        it["suspicion_score"] = score
        it["reasons"] = reasons
        if score >= 5:
            flagged_for_ai.append({
                "rel_path": it["rel_path"],
                "hashes": {"md5": it["md5"], "sha1": it["sha1"], "sha256": it["sha256"]},
                "file_type": it["file_type"],
                "size": it["size"],
                "imports": imports,
                "strings": it.get("strings", [])[:100],
                "iocs": it.get("iocs", {}),
                "reasons": reasons,
                "pseudocode": pseudocode_snippets[:5],
            })

    # 6) DeepSeek
    ai_results: List[Dict] = []
    if use_deepseek and flagged_for_ai:
        ai_results = analyze_with_deepseek(flagged_for_ai)
        ai_dir = os.path.join(out_dir, "ai")
        os.makedirs(ai_dir, exist_ok=True)
        for r in ai_results:
            sha = r.get("item", {}).get("hashes", {}).get("sha256") or "unknown"
            with open(os.path.join(ai_dir, sha + ".json"), "w", encoding="utf-8") as f:
                json.dump(r, f, indent=2, ensure_ascii=False)

    # 5) Aggregate
    aggregated = {
        "rootfs": rootfs,
        "candidates": candidates,
        "static": static_items,
        "virustotal": vt_results,
        "flagged_for_ai": flagged_for_ai,
        "ai_results": ai_results,
        "unpacked_files": unpacked_files,
        "upx_available": is_upx_available(),
    }

    # 8) Reporting
    generate_ai_report(aggregated, out_dir)
    if verbose:
        print("[pipeline] Report written: report.md and report.json")
    return aggregated


