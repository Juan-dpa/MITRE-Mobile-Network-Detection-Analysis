from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "test_logs"
ROLES = (
    ("ftp", "ftp_target.ftp_target"),
    ("c2", "c2.c2_server"),
    ("gw", "gateway.gateway"),
    ("victim", "victim.victim_proxy"),
)


def main() -> None:
    LOG_DIR.mkdir(exist_ok=True)
    processes: list[subprocess.Popen[bytes]] = []
    handles = []
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        for name, module in ROLES:
            stdout = (LOG_DIR / f"{name}.out.log").open("wb")
            stderr = (LOG_DIR / f"{name}.err.log").open("wb")
            handles.extend((stdout, stderr))
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-u", "-m", module],
                    cwd=ROOT,
                    stdout=stdout,
                    stderr=stderr,
                    creationflags=creationflags,
                )
            )
            if name == "gw":
                time.sleep(0.4)

        marker = b"LAB FLOW COMPLETED SUCCESSFULLY"
        deadline = time.monotonic() + 15
        c2_log = LOG_DIR / "c2.err.log"
        while time.monotonic() < deadline:
            if marker in c2_log.read_bytes():
                break
            failed = [
                f"{name} exited with {process.returncode}"
                for (name, _), process in zip(ROLES, processes)
                if process.poll() is not None
            ]
            if failed:
                raise RuntimeError("; ".join(failed))
            time.sleep(0.2)
        else:
            raise TimeoutError("The full flow did not complete within 15 seconds")

        victim = processes[-1]
        victim.wait(timeout=3)
        if victim.returncode != 0:
            raise RuntimeError(f"victim exited with {victim.returncode}")
        if processes[1].poll() is not None:
            raise RuntimeError("C2 server stopped before the finite victim completed")
        print("INTEGRATION_OK")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for handle in handles:
            handle.close()

    for name, _ in ROLES:
        print(f"\n===== {name}.err.log =====")
        print((LOG_DIR / f"{name}.err.log").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
