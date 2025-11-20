import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from .utils import (
    ensure_dir,
    file_kind_from_lstat,
    harden_directory_windows,
    write_json,
)

def ingest(file_path: str, base_dir: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Ingest a single executable/binary by copying it into an isolated sandbox.
    Returns (work_dir, root_dir, manifest_path). Caller must delete work_dir when done.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")

    # Prefer explicit base_dir, then SANDBOX_BASE_DIR env, then repo-root/sandboxes
    if base_dir is None:
        base_dir = os.getenv("SANDBOX_BASE_DIR")
    if base_dir is None:
        project_root = Path(__file__).resolve().parents[1]
        base_dir = str(project_root / "sandboxes")
    ensure_dir(base_dir)

    work_dir = tempfile.mkdtemp(prefix="malware-ingest-", dir=base_dir)
    harden_directory_windows(work_dir)
    root_dir = os.path.join(work_dir, "rootfs")
    ensure_dir(root_dir)

    dest_path = os.path.join(root_dir, os.path.basename(file_path))
    shutil.copy2(file_path, dest_path)

    manifest_path = os.path.join(work_dir, "manifest.json")
    manifest = build_file_manifest(root_dir)
    write_json(manifest_path, manifest)
    return work_dir, root_dir, manifest_path


def build_file_manifest(root_dir: str) -> Dict:
    """
    Walk the extracted rootfs and record file metadata:
    - relpath, kind (file/dir/symlink/special), size, mode (octal), is_executable
    """
    entries: List[Dict] = []
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
        # Directories
        for d in dirnames:
            p = os.path.join(dirpath, d)
            rel = os.path.relpath(p, root_dir)
            try:
                st = os.lstat(p)
                kind = file_kind_from_lstat(st)
                entries.append({
                    "path": rel.replace("\\", "/"),
                    "kind": kind,
                    "size": 0,
                    "mode": oct(st.st_mode & 0o777),
                    "is_executable": bool(st.st_mode & 0o111),
                })
            except Exception:
                pass
        # Files
        for f in filenames:
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, root_dir)
            try:
                st = os.lstat(p)
                kind = file_kind_from_lstat(st)
                size = st.st_size if kind == "file" else 0
                entries.append({
                    "path": rel.replace("\\", "/"),
                    "kind": kind,
                    "size": int(size),
                    "mode": oct(st.st_mode & 0o777),
                    "is_executable": bool(st.st_mode & 0o111),
                })
            except Exception:
                pass
    return {"root": root_dir, "count": len(entries), "files": entries}


