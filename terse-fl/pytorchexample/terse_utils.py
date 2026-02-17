"""TERSE utility functions and automatic setup."""

from __future__ import annotations

import sys
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Paths - use resolve() to get absolute paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # Go up to main project root
DATA_DIR = PROJECT_ROOT / "data"
PYTHON_DIR = PROJECT_ROOT / "python"
SETUP_CLIENTS_BIN = PROJECT_ROOT / "setup_clients"
SETUP_TRUSTED_BIN = PROJECT_ROOT / "setup_trusted"

# Add python directory to path for terse_py module
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

# Quantization parameters (defaults; runtime uses run_config values)
PLAINTEXT_MODULUS = 65537
SCALE_FACTOR = 1000


def get_terse_module():
    """Import and return the terse_py module."""
    try:
        import terse_py  # type: ignore
        return terse_py
    except ImportError as e:
        raise ImportError(
            f"Failed to import terse_py. Make sure you've run 'make python' "
            f"in the project root. Error: {e}\n"
            f"Expected location: {PYTHON_DIR}"
        )


def _read_int(p: Path) -> int:
    return int(p.read_text().strip())


def _read_float(p: Path) -> float:
    return float(p.read_text().strip())


def _setup_bins_exist() -> None:
    if not SETUP_CLIENTS_BIN.exists():
        raise FileNotFoundError(
            f"setup_clients binary not found at {SETUP_CLIENTS_BIN}. "
            f"Run 'make' in the project root first."
        )
    if not SETUP_TRUSTED_BIN.exists():
        raise FileNotFoundError(
            f"setup_trusted binary not found at {SETUP_TRUSTED_BIN}. "
            f"Run 'make' in the project root first."
        )


def is_setup_complete(n_clients: int, n_timestamps: int, vector_dim: int) -> bool:
    """
    Legacy completeness check (old mode).
    """
    required_files = [
        DATA_DIR / "params.bin",
        DATA_DIR / "server_key.bin",
        DATA_DIR / "client_keys.bin",
        DATA_DIR / "n_clients.txt",
        DATA_DIR / "n_timestamps.txt",
        DATA_DIR / "vector_dim.txt",
    ]

    for f in required_files:
        if not f.exists():
            return False

    for i in range(n_clients):
        if not (DATA_DIR / f"client_precompute_{i}.bin").exists():
            return False

    try:
        saved_clients = _read_int(DATA_DIR / "n_clients.txt")
        saved_timestamps = _read_int(DATA_DIR / "n_timestamps.txt")
        saved_vector_dim = _read_int(DATA_DIR / "vector_dim.txt")

        return (
            saved_clients >= n_clients
            and saved_timestamps >= n_timestamps
            and saved_vector_dim >= vector_dim
        )
    except Exception:
        return False


def is_setup_complete_rounds(
    n_clients: int,
    n_rounds: int,
    n_chunks: int,
    vector_dim: int,
    *,
    fraction_fit: Optional[float] = None,
) -> bool:
    """
    New completeness check for round-based sampling mode.

    Note: n_chunks MUST match exactly because mapping round = timestamp / n_chunks
    is baked into server_key.bin precomputation.
    """
    required_files = [
        DATA_DIR / "params.bin",
        DATA_DIR / "server_key.bin",
        DATA_DIR / "client_keys.bin",
        DATA_DIR / "schedule.bin",
        DATA_DIR / "n_clients.txt",
        DATA_DIR / "n_rounds.txt",
        DATA_DIR / "n_chunks.txt",
        DATA_DIR / "n_timestamps.txt",
        DATA_DIR / "vector_dim.txt",
        DATA_DIR / "k_per_round.txt",
        DATA_DIR / "fraction_fit.txt",
    ]

    for f in required_files:
        if not f.exists():
            return False

    for i in range(n_clients):
        if not (DATA_DIR / f"client_precompute_{i}.bin").exists():
            return False

    try:
        saved_clients = _read_int(DATA_DIR / "n_clients.txt")
        saved_rounds = _read_int(DATA_DIR / "n_rounds.txt")
        saved_chunks = _read_int(DATA_DIR / "n_chunks.txt")
        saved_timestamps = _read_int(DATA_DIR / "n_timestamps.txt")
        saved_vector_dim = _read_int(DATA_DIR / "vector_dim.txt")
        saved_fraction = _read_float(DATA_DIR / "fraction_fit.txt")

        want_timestamps = int(n_rounds) * int(n_chunks)

        ok = (
            saved_clients >= n_clients
            and saved_rounds >= n_rounds
            and saved_chunks == n_chunks
            and saved_timestamps >= want_timestamps
            and saved_vector_dim >= vector_dim
        )
        if not ok:
            return False

        if fraction_fit is not None and saved_fraction != float(fraction_fit):
            return False

        return True
    except Exception:
        return False


def run_terse_setup(n_clients: int, n_timestamps: int, vector_dim: int) -> None:
    """
    Legacy setup runner (old mode):
      setup_trusted <n_clients> <n_timestamps> [vector_dim]
      setup_clients <n_clients> <n_timestamps> [vector_dim]
    """
    if is_setup_complete(n_clients, n_timestamps, vector_dim):
        print(
            f"[TERSE] Setup already complete for {n_clients} clients, "
            f"{n_timestamps} timestamps, vector_dim={vector_dim}"
        )
        return

    print(
        f"[TERSE] Running setup (legacy) for {n_clients} clients, "
        f"{n_timestamps} timestamps, vector_dim={vector_dim}..."
    )

    DATA_DIR.mkdir(exist_ok=True)
    _setup_bins_exist()

    print("[TERSE] Running setup_trusted (legacy args)...")
    result = subprocess.run(
        [str(SETUP_TRUSTED_BIN), str(n_clients), str(n_timestamps), str(vector_dim)],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"setup_trusted failed: {result.stderr}")
    print(result.stdout)

    print("[TERSE] Running setup_clients (legacy args)...")
    result = subprocess.run(
        [str(SETUP_CLIENTS_BIN), str(n_clients), str(n_timestamps), str(vector_dim)],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"setup_clients failed: {result.stderr}")
    print(result.stdout)

    print("[TERSE] Setup complete!")


def run_terse_setup_rounds(
    n_clients: int,
    n_rounds: int,
    n_chunks: int,
    vector_dim: int,
    *,
    fraction_fit: float = 1.0,
    schedule_seed: Optional[int] = None,
) -> None:
    """
    Round-based setup runner (sampling schedule generated in trusted setup):

      setup_trusted <n_clients> <n_rounds> <n_chunks> <vector_dim> <fraction_fit> [schedule_seed]
      setup_clients <n_clients> <n_rounds> <n_chunks> <vector_dim>

    Requires updated C++ binaries.
    """
    if is_setup_complete_rounds(
        n_clients, n_rounds, n_chunks, vector_dim, fraction_fit=fraction_fit
    ):
        print(
            f"[TERSE] Setup already complete for n_clients={n_clients}, "
            f"n_rounds={n_rounds}, n_chunks={n_chunks}, vector_dim={vector_dim}, "
            f"fraction_fit={fraction_fit}"
        )
        return

    print(
        f"[TERSE] Running setup (round-based) for n_clients={n_clients}, "
        f"n_rounds={n_rounds}, n_chunks={n_chunks}, vector_dim={vector_dim}, "
        f"fraction_fit={fraction_fit}..."
    )

    DATA_DIR.mkdir(exist_ok=True)
    _setup_bins_exist()

    trusted_cmd = [
        str(SETUP_TRUSTED_BIN),
        str(n_clients),
        str(n_rounds),
        str(n_chunks),
        str(vector_dim),
        str(float(fraction_fit)),
    ]
    if schedule_seed is not None:
        trusted_cmd.append(str(int(schedule_seed)))

    print("[TERSE] Running setup_trusted (round-based args)...")
    result = subprocess.run(
        trusted_cmd,
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"setup_trusted failed: {result.stderr}")
    print(result.stdout)

    print("[TERSE] Running setup_clients (round-based args)...")
    result = subprocess.run(
        [str(SETUP_CLIENTS_BIN), str(n_clients), str(n_rounds), str(n_chunks), str(vector_dim)],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"setup_clients failed: {result.stderr}")
    print(result.stdout)

    print("[TERSE] Setup complete!")


def quantize_parameters(flat_array, scale_factor: int, plaintext_mod: int):
    """Convert float array to quantized uint32 for encryption."""
    import numpy as np

    scaled = np.rint(flat_array.astype(np.float64) * scale_factor).astype(np.int64)
    quantized = np.mod(scaled, plaintext_mod).astype(np.uint32)
    return quantized


def dequantize_parameters(quantized_array, scale_factor: int, plaintext_mod: int):
    """Convert quantized uint32 back to float array."""
    import numpy as np

    values = quantized_array.astype(np.int64)
    half_mod = plaintext_mod // 2
    values = np.where(values > half_mod, values - plaintext_mod, values)
    return values.astype(np.float32) / scale_factor


# ----------------------------
# pyproject.toml configuration
# ----------------------------

@dataclass(frozen=True)
class ClippingConfig:
    enabled: bool = False
    l2_clip_norm: float = 0.0


@dataclass(frozen=True)
class DPConfig:
    enabled: bool = False
    mechanism: str = "none"  # "none" | "laplace" | "gaussian"
    epsilon: float = 0.0
    delta: float = 0.0
    sensitivity: int = 0  # quantized integer sensitivity; 0 => auto from clipping


def _load_pyproject() -> dict:
    """
    Loads PROJECT_ROOT/terse-fl/pyproject.toml.
    Kept intentionally local to this demo layout.
    """
    pyproject = PROJECT_ROOT / "terse-fl" / "pyproject.toml"
    if not pyproject.exists():
        return {}

    try:
        import tomllib  # Python 3.11+
    except Exception as e:
        raise RuntimeError(f"tomllib unavailable; cannot read {pyproject}: {e}")

    return tomllib.loads(pyproject.read_text())


def load_clipping_config() -> ClippingConfig:
    data = _load_pyproject()
    cfg = data.get("tool", {}).get("terse", {}).get("clipping", {})

    enabled = bool(cfg.get("enabled", False))
    l2_clip_norm = float(cfg.get("l2_clip_norm", 0.0))

    if enabled and l2_clip_norm <= 0.0:
        raise ValueError("Clipping enabled but l2_clip_norm <= 0")

    return ClippingConfig(enabled=enabled, l2_clip_norm=l2_clip_norm)


def load_dp_config() -> DPConfig:
    data = _load_pyproject()
    cfg = data.get("tool", {}).get("terse", {}).get("dp", {})

    enabled = bool(cfg.get("enabled", False))
    mechanism = str(cfg.get("mechanism", "none")).lower()
    epsilon = float(cfg.get("epsilon", 0.0))
    delta = float(cfg.get("delta", 0.0))
    sensitivity = int(cfg.get("sensitivity", 0))

    if mechanism not in {"none", "laplace", "gaussian"}:
        raise ValueError(f"Unknown DP mechanism: {mechanism}")

    if enabled and mechanism == "none":
        # allow enabled=true + mechanism=none, but it is effectively off
        enabled = False

    if enabled:
        if epsilon <= 0.0:
            raise ValueError("DP enabled but epsilon <= 0")
        if mechanism == "gaussian":
            if not (0.0 < delta < 1.0):
                raise ValueError("Gaussian DP requires delta in (0, 1)")
        if sensitivity < 0:
            raise ValueError("DP sensitivity must be >= 0 (0 means auto)")

    return DPConfig(
        enabled=enabled,
        mechanism=mechanism,
        epsilon=epsilon,
        delta=delta,
        sensitivity=sensitivity,
    )
