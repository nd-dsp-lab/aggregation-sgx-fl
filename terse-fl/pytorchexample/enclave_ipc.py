import atexit
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class EnclaveDPConfig:
    """
    DP configuration that is passed over IPC to the enclave.

    dp_mech:
      - 0: none
      - 1: laplace
      - 2: gaussian
    """
    dp_mech: int = 0
    epsilon: float = 0.0
    delta: float = 0.0
    sensitivity: int = 0


class PersistentTrustedRound:
    """
    Keeps ONE `gramine-sgx sgx/trusted_round` process alive and reuses it.

    Protocol (line-based):
      - Python -> Enclave:
          "DECRYPT <start_ts> <n_chunks> <vector_dim> <dp_mech> <epsilon> <delta> <sensitivity>\\n"
      - Enclave -> Python: "OK\\n" or "ERR <message>\\n"
      - Python -> Enclave: "QUIT\\n"
      - Enclave -> Python: "OK\\n"
    """

    def __init__(
        self,
        project_root: Path,
        cmd: Optional[list[str]] = None,
        cwd: Optional[Path] = None,
        stderr_path: Optional[Path] = None,
    ):
        self.project_root = Path(project_root).resolve()
        self.cwd = Path(cwd).resolve() if cwd is not None else self.project_root

        # Default command uses the canonical SGX runtime layout:
        #   <project_root>/sgx/trusted_round
        #   <project_root>/sgx/trusted_round.manifest.sgx
        #
        # Note: do NOT .resolve() the sgx/trusted_round path; it may be a symlink
        # and Gramine locates the manifest next to the path you execute.
        if cmd is None:
            trusted_round_path = self.project_root / "sgx" / "trusted_round"
            manifest_sgx_path = self.project_root / "sgx" / "trusted_round.manifest.sgx"

            if not trusted_round_path.exists():
                raise FileNotFoundError(
                    f"SGX launcher not found: {trusted_round_path}\n"
                    f"Run `make sgx` in {self.project_root} (it should create sgx/trusted_round)."
                )
            if not manifest_sgx_path.exists():
                raise FileNotFoundError(
                    f"SGX manifest not found: {manifest_sgx_path}\n"
                    f"Run `make sgx` in {self.project_root} (it should create sgx/trusted_round.manifest.sgx)."
                )

            self.cmd = ["gramine-sgx", str(trusted_round_path)]
        else:
            self.cmd = cmd

        self._stderr_file = None
        if stderr_path is not None:
            stderr_path = Path(stderr_path)
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            self._stderr_file = open(stderr_path, "a", buffering=1)

        self.p = subprocess.Popen(
            self.cmd,
            cwd=str(self.cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file if self._stderr_file is not None else subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        if self.p.stdin is None or self.p.stdout is None:
            raise RuntimeError("Failed to open stdin/stdout pipes to enclave process")

        self._stop_stderr = threading.Event()
        self._stderr_thread = None
        if self._stderr_file is None and self.p.stderr is not None:
            self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
            self._stderr_thread.start()

        atexit.register(self.close)

    def _drain_stderr(self) -> None:
        try:
            while not self._stop_stderr.is_set():
                line = self.p.stderr.readline()  # type: ignore[union-attr]
                if not line:
                    return
        except Exception:
            return

    def _readline(self) -> str:
        line = self.p.stdout.readline()
        if line == "":
            rc = self.p.poll()
            raise RuntimeError(f"trusted_round exited unexpectedly (returncode={rc})")
        return line.rstrip("\n")

    def decrypt_round(
        self,
        start_ts: int,
        n_chunks: int,
        vector_dim: int,
        dp: Optional[EnclaveDPConfig] = None,
    ) -> None:
        if self.p.poll() is not None:
            raise RuntimeError("trusted_round process is not running")

        dp = dp or EnclaveDPConfig()

        self.p.stdin.write(
            f"DECRYPT {start_ts} {n_chunks} {vector_dim} "
            f"{dp.dp_mech} {dp.epsilon} {dp.delta} {dp.sensitivity}\n"
        )
        self.p.stdin.flush()

        resp = self._readline()
        if resp == "OK":
            return
        raise RuntimeError(f"trusted_round error: {resp}")

    def close(self) -> None:
        if getattr(self, "p", None) is None:
            return
        if self.p.poll() is not None:
            return

        try:
            if self.p.stdin is not None:
                self.p.stdin.write("QUIT\n")
                self.p.stdin.flush()
            try:
                _ = self._readline()
            except Exception:
                pass
        finally:
            try:
                self._stop_stderr.set()
            except Exception:
                pass

            try:
                self.p.terminate()
            except Exception:
                pass

            try:
                self.p.wait(timeout=5)
            except Exception:
                try:
                    self.p.kill()
                except Exception:
                    pass

            try:
                if self._stderr_file is not None:
                    self._stderr_file.close()
            except Exception:
                pass
