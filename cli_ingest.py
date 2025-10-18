import argparse
import logging
import os
import sys

from pipeline.ingestion import ingest
from pipeline.utils import write_json

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def main():
    parser = argparse.ArgumentParser(description="Phase 1: Ingest Docker image or tarball and securely extract files")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--image", help="Docker image name, e.g. ubuntu:20.04")
    group.add_argument("--tar", help="Path to Docker image tar (docker save or docker export tar)")
    parser.add_argument("--out", default="outputs", help="Directory to copy manifest and a link to sandbox")
    parser.add_argument("--sandbox-base", help="Base directory for sandbox storage (default: repo sandboxes/ or SANDBOX_BASE_DIR)")
    args = parser.parse_args()

    target = args.image or args.tar
    try:
        work_dir, root_dir, manifest_path = ingest(target, base_dir=args.sandbox_base)
    except Exception as e:
        print(f"Error: {e}")
        print("Tip: Ensure Docker Desktop is running, Linux containers are enabled, and 'docker info' works.")
        return 1

    # Persist manifest and a pointer to the sandbox
    os.makedirs(args.out, exist_ok=True)
    final_manifest = os.path.join(args.out, "ingestion_manifest.json")
    # Copy manifest (sandbox stays in temp for isolation; we record its path)
    write_json(final_manifest, {"sandbox": work_dir, "rootfs": root_dir, "manifest_path": manifest_path})

    print(f"Sandbox: {work_dir}")
    print(f"RootFS:  {root_dir}")
    print(f"Manifest copied to: {final_manifest}")


if __name__ == "__main__":
    sys.exit(main())


