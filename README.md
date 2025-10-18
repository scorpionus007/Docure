Malware Analysis Pipeline — Phase 1 (Ingestion)

This phase ingests a Docker image (by name) or a Docker tarball and securely reconstructs the root filesystem into a hardened, temporary sandbox. It outputs a JSON manifest with file metadata.

Usage (PowerShell):

```
py -m pip install -r requirements.txt
py cli_ingest.py --image ubuntu:20.04 --out outputs
# or
py cli_ingest.py --tar C:\path\to\image.tar --out outputs
```

Artifacts:
- A temporary sandbox directory (path shown after run)
- Extracted root filesystem under the sandbox
- `outputs/ingestion_manifest.json` pointing to the sandbox and manifest

Security:
- Safe tar extraction with path traversal checks
- Best-effort ACL hardening on Windows (non-fatal if not permitted)
- Whiteout handling for `docker save` tarballs to reconstruct layered filesystems

Requirements:
- Python 3.10+
- Docker Desktop (Linux containers)

Sandbox location and overrides:
- By default, sandboxes are created under `<repo>/sandboxes/`.
- Override with an environment variable or CLI flag:
  - Env: `setx SANDBOX_BASE_DIR "D:\malware-sandboxes"`
  - CLI: `--sandbox-base D:\malware-sandboxes`
  - Example:
    - `py cli_ingest.py --image ubuntu:20.04 --out outputs --sandbox-base "C:\\Users\\aryan\\OneDrive\\Desktop\\docker malware analysis\\sandboxes"`

Troubleshooting (Windows):
- Ensure Docker Desktop is running and switched to Linux containers.
- Open a new PowerShell and verify `docker info` works.
- If you see `CreateFile ... The system cannot find the file specified`, the Docker named pipe `\\.\\pipe\\docker_engine` is not available. Start Docker Desktop.
- Add your user to the `docker-users` group and sign out/in if needed.
- If using a remote daemon, set `DOCKER_HOST` accordingly (default is the Windows named pipe above).

Next:
- Static analysis, VirusTotal integration, AI summarization, and reporting will build on this sandbox.


