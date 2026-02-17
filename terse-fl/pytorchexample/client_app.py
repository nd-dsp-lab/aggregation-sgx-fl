"""TERSE-FL Client App with encrypted model updates."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

import numpy as np
import torch
import traceback
from flwr.client import ClientApp, NumPyClient
from flwr.common import Context

from pytorchexample.task import Net, load_data, test, train
from pytorchexample.terse_utils import (
    DATA_DIR,
    PROJECT_ROOT,
    get_terse_module,
    load_clipping_config,
    quantize_parameters,
)


def _flatten_params_list(params_list):
    if params_list is None or len(params_list) == 0:
        raise ValueError("Received empty parameters from server (global model is missing)")
    return np.concatenate([p.reshape(-1).astype(np.float32, copy=False) for p in params_list])


def _flatten_model_params(model: torch.nn.Module) -> np.ndarray:
    return np.concatenate(
        [p.detach().cpu().numpy().reshape(-1).astype(np.float32, copy=False) for p in model.parameters()]
    )

def _ndarrays_from_state_dict(model: torch.nn.Module) -> list[np.ndarray]:
    # Stable ordering (matches state_dict keys/values order)
    return [v.detach().cpu().numpy() for v in model.state_dict().values()]

def _assert_finite_params(params: List[np.ndarray], where: str, pid: int) -> None:
    max_abs = 0.0
    for i, p in enumerate(params):
        arr = np.asarray(p)
        if not np.all(np.isfinite(arr)):
            bad = np.logical_not(np.isfinite(arr))
            raise ValueError(
                f"Non-finite {where} params on pid={pid}, tensor_idx={i}, "
                f"bad_count={int(bad.sum())}, shape={arr.shape}"
            )
        if arr.size:
            max_abs = max(max_abs, float(np.max(np.abs(arr))))
    # Comment this out if too noisy
    # print(f"[pid={pid}] {where} params max|x|={max_abs:.6g}")


class TERSEFlowerClient(NumPyClient):
    """Flower client that encrypts model updates with TERSE."""

    def __init__(
        self,
        partition_id: int,
        num_partitions: int,
        batch_size: int,
        local_epochs: int,
        learning_rate: float,
        scale_factor: int,
        plaintext_modulus: int,
        vector_dim: int,
    ) -> None:
        self.partition_id = int(partition_id)
        self.num_partitions = int(num_partitions)
        self.batch_size = int(batch_size)
        self.local_epochs = int(local_epochs)
        self.learning_rate = float(learning_rate)
        self.scale_factor = int(scale_factor)
        self.plaintext_modulus = int(plaintext_modulus)
        self.vector_dim = int(vector_dim)

        self.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

        self.trainloader, self.valloader = load_data(
            self.partition_id, self.num_partitions, self.batch_size
        )

        self.clipping_cfg = load_clipping_config()

        terse_py = get_terse_module()
        params_file = str(DATA_DIR / "params.bin")

        original_cwd = os.getcwd()
        try:
            os.chdir(PROJECT_ROOT)
            self.terse_client = terse_py.TERSEClient(params_file, self.partition_id)
        finally:
            os.chdir(original_cwd)

    def get_properties(self, config: Dict[str, Any]) -> Dict[str, Any]:
        return {"partition_id": int(self.partition_id)}

    def get_parameters(self, config):
        # Flower calls this (e.g., to get initial parameters)
        model = Net().to(self.device)
        return _ndarrays_from_state_dict(model)

    def set_parameters(self, model: Net, parameters: List[np.ndarray]) -> None:
        # Load parameters into model in state_dict key order
        keys = list(model.state_dict().keys())
        if len(keys) != len(parameters):
            raise ValueError(
                f"Parameter length mismatch on pid={self.partition_id}: "
                f"got {len(parameters)} arrays, expected {len(keys)}"
            )

        state_dict = {}
        for k, v in zip(keys, parameters):
            t = torch.from_numpy(np.asarray(v)).to(dtype=torch.float32, device=self.device)
            state_dict[k] = t

        model.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        server_round = int(config.get("server_round", 1))

        try:
            # 1) Check incoming global parameters
            _assert_finite_params(parameters, where="INCOMING", pid=self.partition_id)

            model = Net().to(self.device)
            self.set_parameters(model, parameters)

            server_flat = _flatten_params_list(parameters)
            if not np.all(np.isfinite(server_flat)):
                raise FloatingPointError("Non-finite server_flat (incoming global params)")

            # 2) Local training
            train_loss = train(
                model,
                self.trainloader,
                self.local_epochs,
                self.learning_rate,
                self.device,
            )

            # 3) Check trained model params are finite
            trained_params = _ndarrays_from_state_dict(model)
            _assert_finite_params(trained_params, where="TRAINED", pid=self.partition_id)

            trained_flat = _flatten_params_list(trained_params)
            if not np.all(np.isfinite(trained_flat)):
                raise FloatingPointError("Non-finite trained_flat (after local training)")

            # 4) Check delta is finite before encryption
            delta = trained_flat - server_flat
            if not np.all(np.isfinite(delta)):
                raise FloatingPointError("Non-finite delta (trained - server)")

            # 5) Encrypt update
            encrypted_chunks = self.get_encrypted_update_chunks(
                model=model,
                server_round=server_round,
                server_flat=server_flat,
            )

            return encrypted_chunks, len(self.trainloader.dataset), {
                "train_loss": float(train_loss),
                "partition_id": int(self.partition_id),
                "client_diverged": 0,
            }

        except (FloatingPointError, ValueError) as e:
            # Explicit “math went bad” signal; no ciphertext returned.
            msg = (
                f"[client {self.partition_id}] Diverged at round {server_round}: {e}\n"
                f"{traceback.format_exc()}"
            )
            raise FloatingPointError(msg) from e

        except Exception as e:
            # Any other failure: also fail the round, don’t contribute an update.
            msg = (
                f"[client {self.partition_id}] fit() failed at round {server_round}: {e}\n"
                f"{traceback.format_exc()}"
            )
            raise RuntimeError(msg) from e



    def evaluate(
        self, parameters: List[np.ndarray], config: Dict[str, Any]
    ) -> Tuple[float, int, Dict[str, Any]]:
        _assert_finite_params(parameters, where="EVAL_INCOMING", pid=self.partition_id)

        model = Net().to(self.device)
        self.set_parameters(model, parameters)

        loss, accuracy = test(model, self.valloader, self.device)
        return float(loss), len(self.valloader.dataset), {"accuracy": float(accuracy)}

    def get_encrypted_update_chunks(
        self,
        model: Net,
        server_round: int,
        server_flat: np.ndarray,
    ) -> List[np.ndarray]:
        trained_flat = _flatten_model_params(model)

        if not np.all(np.isfinite(trained_flat)):
            raise ValueError(f"Non-finite TRAINED params on pid={self.partition_id}")

        delta = trained_flat - server_flat
        if not np.all(np.isfinite(delta)):
            raise ValueError(f"Non-finite DELTA on pid={self.partition_id}")

        # Optional L2 clipping on delta
        if self.clipping_cfg.enabled:
            c = float(self.clipping_cfg.l2_clip_norm)
            delta64 = delta.astype(np.float64, copy=False)
            l2 = float(np.linalg.norm(delta64, ord=2))
            if l2 > c:
                delta = delta * (c / (l2 + 1e-12))

        padded_len = ((len(delta) + self.vector_dim - 1) // self.vector_dim) * self.vector_dim
        padded_delta = np.zeros(padded_len, dtype=np.float32)
        padded_delta[: len(delta)] = delta

        quantized = quantize_parameters(padded_delta, self.scale_factor, self.plaintext_modulus)

        n_chunks = padded_len // self.vector_dim
        encrypted_chunks: List[np.ndarray] = []

        for chunk_idx in range(n_chunks):
            start = chunk_idx * self.vector_dim
            end = start + self.vector_dim
            chunk = quantized[start:end]

            timestamp = (server_round - 1) * n_chunks + chunk_idx
            encrypted = self.terse_client.encrypt_vector(chunk, timestamp)
            encrypted_chunks.append(encrypted)

        return encrypted_chunks


def client_fn(context: Context):
    partition_id = int(context.node_config["partition-id"])
    num_partitions = int(context.node_config["num-partitions"])

    batch_size = int(context.run_config["batch-size"])
    local_epochs = int(context.run_config["local-epochs"])
    learning_rate = float(context.run_config["learning-rate"])
    scale_factor = int(context.run_config["scale-factor"])
    plaintext_modulus = int(context.run_config["plaintext-modulus"])
    vector_dim = int(context.run_config["vector-dim"])

    client = TERSEFlowerClient(
        partition_id=partition_id,
        num_partitions=num_partitions,
        batch_size=batch_size,
        local_epochs=local_epochs,
        learning_rate=learning_rate,
        scale_factor=scale_factor,
        plaintext_modulus=plaintext_modulus,
        vector_dim=vector_dim,
    )
    return client.to_client()

def _model_param_count_from_parameters(parameters: list[np.ndarray]) -> int:
    return int(sum(np.asarray(p).size for p in parameters))


def _encrypt_zero_update(
    terse_client,
    server_round: int,
    vector_dim: int,
    model_param_count: int,
) -> list[np.ndarray]:
    padded_len = ((model_param_count + vector_dim - 1) // vector_dim) * vector_dim
    n_chunks = padded_len // vector_dim

    zero_chunk = np.zeros(vector_dim, dtype=np.uint64)
    out: list[np.ndarray] = []
    for chunk_idx in range(n_chunks):
        timestamp = (server_round - 1) * n_chunks + chunk_idx
        out.append(terse_client.encrypt_vector(zero_chunk, timestamp))
    return out


app = ClientApp(client_fn=client_fn)
