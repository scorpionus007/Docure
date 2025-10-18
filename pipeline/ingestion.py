import io
import json
import logging
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import docker
import docker.errors

from .utils import (
    ensure_dir,
    file_kind_from_lstat,
    harden_directory_windows,
    is_within_directory,
    safe_extract_tarfile,
    write_json,
)

log = logging.getLogger(__name__)


def ingest(image_or_tar: str, base_dir: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Ingest a Docker image (by name) or Docker image tarball.
    Returns (work_dir, root_dir, manifest_path). Caller must delete work_dir when done.
    """
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

    if os.path.isfile(image_or_tar):
        _extract_from_tarball(image_or_tar, root_dir)
    else:
        _extract_from_image(image_or_tar, root_dir)

    manifest_path = os.path.join(work_dir, "manifest.json")
    manifest = build_file_manifest(root_dir)
    write_json(manifest_path, manifest)
    return work_dir, root_dir, manifest_path


def _extract_from_image(image: str, root_dir: str):
    """
    Create a temporary container and export its filesystem.
    """
    log.info(f"Exporting filesystem for image: {image}")
    # Check Docker daemon connectivity early with a friendly error
    try:
        client = docker.from_env()
        try:
            client.ping()
        except Exception as e:
            raise RuntimeError(
                "Docker daemon is not reachable. Ensure Docker Desktop is running, switched to Linux containers, and 'docker info' works in this PowerShell session."
            ) from e
    except docker.errors.DockerException as e:
        raise RuntimeError(
            "Failed to connect to Docker. Start Docker Desktop, or set DOCKER_HOST if using a remote daemon."
        ) from e
    container = None
    tmp_tar = None
    try:
        try:
            container = client.containers.create(image, command="/bin/true")
        except docker.errors.ImageNotFound:
            # Try to pull the image automatically
            try:
                log.info(f"Image not found locally. Pulling: {image}")
                client.images.pull(image)
                container = client.containers.create(image, command="/bin/true")
            except Exception as pull_e:
                raise RuntimeError(
                    f"Docker image not found and pull failed for '{image}'. Try 'docker pull {image}' manually."
                ) from pull_e
        stream = container.export()  # tar stream of container filesystem
        tmp_tar = tempfile.NamedTemporaryFile(delete=False, suffix=".tar")
        for chunk in stream:
            tmp_tar.write(chunk)
        tmp_tar.close()
        with tarfile.open(tmp_tar.name, "r:*") as tf:
            safe_extract_tarfile(tf, root_dir)
    except docker.errors.DockerException as e:
        raise RuntimeError(
            "Docker operation failed. Verify Docker Desktop is running, WSL2 engine is enabled, and you are in the 'docker-users' group."
        ) from e
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception as e:
                log.warning(f"Container cleanup failed: {e}")
        if tmp_tar:
            try:
                os.unlink(tmp_tar.name)
            except Exception:
                pass


def _extract_from_tarball(tar_path: str, root_dir: str):
    """
    Handle two cases:
      - 'docker save' tarball (contains manifest.json and layer tarballs)
      - Flat rootfs tarball (already a container filesystem)
    """
    log.info(f"Extracting from tarball: {tar_path}")
    with tarfile.open(tar_path, "r:*") as tf:
        members = tf.getmembers()
        names = {m.name for m in members}
        if "manifest.json" in names:
            _extract_docker_save(tf, root_dir)
        else:
            # Assume this is a rootfs tar (e.g., from docker export)
            safe_extract_tarfile(tf, root_dir)


def _extract_docker_save(tf: tarfile.TarFile, root_dir: str):
    """
    Reconstruct rootfs by applying layers in order with whiteout handling.
    """
    manifest_member = tf.getmember("manifest.json")
    with tf.extractfile(manifest_member) as mf:
        manifest = json.load(mf)
    # Take first entry; extend if multiple images are present
    layers: List[str] = manifest[0]["Layers"]

    for layer_path in layers:
        layer_member = tf.getmember(layer_path)
        with tf.extractfile(layer_member) as layer_file:
            if not layer_file:
                continue
            with tarfile.open(fileobj=io.BytesIO(layer_file.read()), mode="r:*") as lf:
                _apply_layer_tar(lf, root_dir)


def _apply_layer_tar(lf: tarfile.TarFile, root_dir: str):
    """
    Apply a single layer with Docker whiteout semantics (simplified).
    - .wh.<name> => delete the target path from lower layers
    - .wh..wh..opq => make directory opaque: delete all entries under that directory
    """
    # First handle whiteouts
    for member in lf.getmembers():
        name = member.name.lstrip("./")
        base = os.path.basename(name)
        dirname = os.path.dirname(name)
        if base == ".wh..wh..opq":
            target_dir = os.path.join(root_dir, dirname)
            if is_within_directory(root_dir, target_dir) and os.path.isdir(target_dir):
                for entry in os.listdir(target_dir):
                    p = os.path.join(target_dir, entry)
                    _rm_path(p)
        elif base.startswith(".wh."):
            target_rel = os.path.join(dirname, base[4:])
            target_abs = os.path.join(root_dir, target_rel)
            if is_within_directory(root_dir, target_abs):
                _rm_path(target_abs)

    # Then extract normal members
    for member in lf.getmembers():
        name = member.name.lstrip("./")
        base = os.path.basename(name)
        if base == ".wh..wh..opq" or base.startswith(".wh."):
            continue
        _safe_extract_member(lf, member, root_dir)


def _safe_extract_member(tf: tarfile.TarFile, member: tarfile.TarInfo, dest_dir: str):
    # Reuse the same protections as general extractor
    from .utils import _safe_extract_member as _base_extract
    _base_extract(tf, member, dest_dir)


def _rm_path(path: str):
    try:
        if os.path.islink(path) or os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


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


