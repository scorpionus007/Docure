import argparse
import json
import os
import sys

# Load .env if present
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

from pipeline.orchestrator import analyze_image
from pipeline.ingestion import ingest


def main():
    p = argparse.ArgumentParser(description="Ingest and analyze a Docker image/tar using Ghidra headless and DeepSeek")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--from-manifest", help="Path to ingestion manifest JSON (from cli_ingest.py)")
    g.add_argument("--image", help="Docker image name, e.g. ubuntu:20.04 or ghcr.io/owner/name:tag")
    g.add_argument("--tar", help="Path to Docker image tar (docker save/export)")
    p.add_argument("--out", default="outputs", help="Output directory")
    p.add_argument("--ghidra-home", help="Path to GHIDRA_HOME (overrides env)")
    p.add_argument("--no-deepseek", action="store_true", help="Disable DeepSeek AI analysis")
    p.add_argument("--max-files", type=int, default=200)
    p.add_argument("--max-size-mb", type=int, default=50)
    p.add_argument("--ghidra-timeout-s", type=int, default=300)
    p.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    p.add_argument("--sandbox-base", help="Base directory for sandbox storage (default: SANDBOX_BASE_DIR or repo sandboxes/)")
    args = p.parse_args()

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    try:
        manifest_path = args.from_manifest
        if not manifest_path:
            target = args.image or args.tar
            if args.verbose:
                print(f"[cli] Ingesting target: {target}")
            work_dir, root_dir, manifest_path = ingest(target, base_dir=args.sandbox_base)
            if args.verbose:
                print(f"[cli] Sandbox: {work_dir}")
                print(f"[cli] RootFS:  {root_dir}")
                print(f"[cli] Manifest: {manifest_path}")

        res = analyze_image(
            manifest_path=manifest_path,
            out_dir=out_dir,
            ghidra_home=args.ghidra_home,
            use_deepseek=not args.no_deepseek,
            max_files=args.max_files,
            max_size_mb=args.max_size_mb,
            ghidra_timeout_s=args.ghidra_timeout_s,
            verbose=args.verbose,
        )
    except Exception as e:
        print(f"Error: {e}")
        return 1

    with open(os.path.join(out_dir, "analysis_summary.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("Analysis complete. See outputs under:", out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())


