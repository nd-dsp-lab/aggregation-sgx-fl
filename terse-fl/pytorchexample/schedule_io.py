from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union


@dataclass(frozen=True)
class Schedule:
    n_rounds: int
    k_per_round: int
    schedule_seed: int
    all_clients_every_round: bool
    participants: Optional[List[List[int]]]  # None if all_clients_every_round=True


def load_schedule_bin(path: Union[str, Path]) -> Schedule:
    """
    Load schedule.bin written by updated setup_trusted.cpp.

    Binary layout (little-endian), must match C++:
      uint32 magic        = 0x53455254  ('TRES')
      uint32 version      = 1
      uint32 flags        bit0 => all_clients_every_round
      uint32 n_rounds
      uint32 k_per_round
      uint64 schedule_seed
      if not all_clients_every_round:
         n_rounds * k_per_round * uint32 client_ids
    """
    p = Path(path)
    raw = p.read_bytes()

    off = 0
    if len(raw) < 12 + 8 + 8:
        raise ValueError(f"schedule.bin too small: {len(raw)} bytes")

    (magic, version, flags) = struct.unpack_from("<III", raw, off)
    off += 12

    if magic != 0x53455254:
        raise ValueError(f"Bad magic in schedule.bin: {hex(magic)} (expected 0x53455254)")
    if version != 1:
        raise ValueError(f"Unsupported schedule.bin version: {version}")

    (n_rounds, k_per_round) = struct.unpack_from("<II", raw, off)
    off += 8
    (schedule_seed,) = struct.unpack_from("<Q", raw, off)
    off += 8

    all_clients_every_round = (flags & 1) != 0
    if all_clients_every_round:
        return Schedule(
            n_rounds=int(n_rounds),
            k_per_round=int(k_per_round),
            schedule_seed=int(schedule_seed),
            all_clients_every_round=True,
            participants=None,
        )

    participants: List[List[int]] = []
    for _ in range(int(n_rounds)):
        fmt = f"<{int(k_per_round)}I"
        need = 4 * int(k_per_round)
        if off + need > len(raw):
            raise ValueError("schedule.bin truncated while reading participants")
        ids = list(struct.unpack_from(fmt, raw, off))
        off += need
        participants.append([int(x) for x in ids])

    return Schedule(
        n_rounds=int(n_rounds),
        k_per_round=int(k_per_round),
        schedule_seed=int(schedule_seed),
        all_clients_every_round=False,
        participants=participants,
    )
