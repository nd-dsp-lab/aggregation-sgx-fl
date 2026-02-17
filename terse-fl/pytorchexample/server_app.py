"""TERSE-FL Server App with secure aggregation."""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
from flwr.common import (
    FitIns,
    FitRes,
    GetPropertiesIns,
    Parameters,
    Scalar,
    ndarrays_to_parameters,
    parameters_to_ndarrays,
)
from flwr.common import Context
from flwr.server import ServerApp, ServerAppComponents, ServerConfig
from flwr.server.client_proxy import ClientProxy
from flwr.server.strategy import FedAvg

from pytorchexample.enclave_ipc import EnclaveDPConfig, PersistentTrustedRound
from pytorchexample.schedule_io import Schedule, load_schedule_bin
from pytorchexample.task import Net, count_parameters, load_centralized_dataset, test
from pytorchexample.terse_utils import (
    DATA_DIR,
    PROJECT_ROOT,
    dequantize_parameters,
    get_terse_module,
    load_clipping_config,
    load_dp_config,
    run_terse_setup_rounds,
)


def _flatten_params_list(params_list: list[np.ndarray]) -> np.ndarray:
    return np.concatenate([p.reshape(-1).astype(np.float32) for p in params_list])


class TERSEFedAvg(FedAvg):
    """FedAvg strategy with TERSE secure aggregation (decrypt + DP in SGX)."""

    def __init__(
        self,
        n_clients: int,
        vector_dim: int,
        scale_factor: int,
        plaintext_modulus: int,
        model_param_count: int,
        initial_parameters: Parameters,
        n_server_rounds: int,
        **kwargs,
    ):
        # We override configure_fit, so FedAvg's internal sampling fraction is not used.
        super().__init__(initial_parameters=initial_parameters, **kwargs)

        self.n_clients = int(n_clients)
        self.vector_dim = int(vector_dim)
        self.scale_factor = int(scale_factor)
        self.plaintext_modulus = int(plaintext_modulus)
        self.model_param_count = int(model_param_count)
        self.n_server_rounds = int(n_server_rounds)

        padded_len = ((self.model_param_count + self.vector_dim - 1) // self.vector_dim) * self.vector_dim
        self.n_chunks = padded_len // self.vector_dim
        self.padded_len = padded_len

        terse_py = get_terse_module()
        params_file = str(DATA_DIR / "params.bin")
        self.terse_server = terse_py.TERSEServer(params_file)

        # Maintain current global params locally, so we can apply aggregated updates.
        init_nd = parameters_to_ndarrays(initial_parameters)
        self._current_flat = _flatten_params_list(init_nd).astype(np.float32)
        if self._current_flat.size != self.model_param_count:
            raise ValueError(
                f"Initial param count mismatch: got {self._current_flat.size}, expected {self.model_param_count}"
            )

        # Load DP config once (server side), then pass numeric values to the enclave each round.
        self._dp_cfg = load_dp_config()
        self._clip_cfg = load_clipping_config()
        self._enclave_dp = self._build_enclave_dp_config()

        # Start ONE enclave process and keep it alive.
        self._enclave = PersistentTrustedRound(
            project_root=PROJECT_ROOT,
            cwd=PROJECT_ROOT,
            stderr_path=DATA_DIR / "trusted_round.stderr.log",
        )

        # Load schedule produced by trusted setup
        self._schedule: Schedule = load_schedule_bin(DATA_DIR / "schedule.bin")
        if self._schedule.n_rounds < self.n_server_rounds:
            raise ValueError(
                f"schedule.n_rounds={self._schedule.n_rounds} < requested n_server_rounds={self.n_server_rounds}"
            )

        # Determine required clients per round
        self._k_per_round = (
            self.n_clients if self._schedule.all_clients_every_round else self._schedule.k_per_round
        )

        # Enforce abort-on-failure semantics
        self.accept_failures = False
        self.min_fit_clients = self._k_per_round
        self.min_available_clients = self.n_clients

        # Cache mapping: TERSE client index (partition_id) -> Flower cid
        self._pid_to_cid: Dict[int, str] = {}

    def _build_enclave_dp_config(self) -> EnclaveDPConfig:
        if not self._dp_cfg.enabled:
            return EnclaveDPConfig(dp_mech=0, epsilon=0.0, delta=0.0, sensitivity=0)

        mech_map = {"none": 0, "laplace": 1, "gaussian": 2}
        dp_mech = mech_map[self._dp_cfg.mechanism]

        sensitivity = int(self._dp_cfg.sensitivity)
        if sensitivity == 0:
            if not self._clip_cfg.enabled:
                raise ValueError(
                    "DP sensitivity=0 (auto) but clipping is disabled. "
                    "Enable clipping or set an explicit dp.sensitivity."
                )
            sensitivity = int(round(self._clip_cfg.l2_clip_norm * self.scale_factor))
            if sensitivity <= 0:
                raise ValueError("Derived DP sensitivity <= 0; check clipping norm / scale_factor")

        return EnclaveDPConfig(
            dp_mech=dp_mech,
            epsilon=float(self._dp_cfg.epsilon),
            delta=float(self._dp_cfg.delta),
            sensitivity=int(sensitivity),
        )

    def _load_decrypted_chunk(self, timestamp: int) -> np.ndarray:
        p = DATA_DIR / f"decrypted_{timestamp}.bin"
        raw = p.read_bytes()
        arr = np.frombuffer(raw, dtype=np.uint32, count=self.vector_dim)
        if arr.size != self.vector_dim:
            raise ValueError(
                f"Bad decrypted size for ts={timestamp}: got {arr.size}, expected {self.vector_dim}"
            )
        return arr

    def _guess_group_id(self, client_manager, proxy: ClientProxy) -> str:
        """
        Best-effort group_id discovery for GridClientProxy.

        In some Flower Grid/Ray setups, group_id is not exposed on client_manager
        under `group_id` or `_group_id`. We'll try a few common places and
        otherwise fall back to "default".
        """
        candidates = [
            getattr(client_manager, "group_id", None),
            getattr(client_manager, "_group_id", None),
            getattr(proxy, "group_id", None),
            getattr(proxy, "_group_id", None),
        ]
        for c in candidates:
            if isinstance(c, str) and c:
                return c
        return "default"

    def _get_properties_from_proxy(self, proxy: ClientProxy, client_manager, timeout_s: float) -> dict:
        ins = GetPropertiesIns(config={})

        # Always try Grid signature first: (ins, timeout, group_id)
        group_id = self._guess_group_id(client_manager, proxy)
        try:
            res = proxy.get_properties(ins, timeout_s, group_id)
            props = getattr(res, "properties", res)
            return props
        except TypeError:
            # Fallback for non-grid backends: (ins, timeout)
            res = proxy.get_properties(ins, timeout_s)
            props = getattr(res, "properties", res)
            return props

    def _ensure_pid_mapping(self, client_manager) -> None:
        """Build mapping TERSE partition_id -> Flower cid using get_properties only."""
        if self._pid_to_cid:
            return

        proxies = list(client_manager.all().values())
        if not proxies:
            raise RuntimeError("No clients available")

        timeout_s = 30.0
        pid_to_cid: Dict[int, str] = {}

        for p in proxies:
            props = self._get_properties_from_proxy(p, client_manager, timeout_s)

            if "partition_id" not in props:
                raise RuntimeError(
                    f"Client cid={p.cid} did not return 'partition_id' in get_properties; "
                    f"got keys={list(props.keys())}"
                )

            try:
                pid = int(props["partition_id"])
            except Exception as e:
                raise RuntimeError(
                    f"Client cid={p.cid} returned non-int partition_id={props['partition_id']!r}: {e}"
                )

            if pid < 0 or pid >= self.n_clients:
                raise RuntimeError(
                    f"Client cid={p.cid} has out-of-range partition_id={pid} "
                    f"(expected 0..{self.n_clients - 1})"
                )

            if pid in pid_to_cid:
                raise RuntimeError(
                    f"Duplicate partition_id={pid} claimed by cid={p.cid} and cid={pid_to_cid[pid]}"
                )

            pid_to_cid[pid] = p.cid

        missing = [pid for pid in range(self.n_clients) if pid not in pid_to_cid]
        if missing:
            raise RuntimeError(
                f"pid->cid mapping incomplete: missing pid={missing[0]} "
                f"(have {len(pid_to_cid)} of {self.n_clients})"
            )

        self._pid_to_cid = pid_to_cid

    def initialize_parameters(self, client_manager):
        # Ensure Flower never falls back to client-provided or empty initialization
        return self.initial_parameters
        
    def configure_fit(self, server_round: int, parameters: Parameters, client_manager):
        """Select exactly the scheduled TERSE client indices for this round."""

        proxies = list(client_manager.all().values())
        if len(proxies) != self.n_clients:
            raise RuntimeError(
                f"Expected n_clients={self.n_clients}, but client_manager has {len(proxies)} clients. "
                "Fix Flower launch/config so exactly n_clients clients are available."
            )

        r = server_round - 1
        if r < 0 or r >= self._schedule.n_rounds:
            raise RuntimeError(f"Round {server_round} out of range for schedule")

        if self._schedule.all_clients_every_round:
            scheduled_pids = list(range(self.n_clients))
        else:
            assert self._schedule.participants is not None
            scheduled_pids = self._schedule.participants[r]

        self._ensure_pid_mapping(client_manager)

        by_cid = {p.cid: p for p in proxies}

        selected_cids: List[str] = []
        for pid in scheduled_pids:
            cid = self._pid_to_cid.get(pid)
            if cid is None:
                raise RuntimeError(f"Scheduled pid={pid} not found among available clients")
            selected_cids.append(cid)

        self._expected_cids_for_round = list(selected_cids)
        self._expected_pids_for_round = list(scheduled_pids)

        missing = [cid for cid in selected_cids if cid not in by_cid]
        if missing:
            raise RuntimeError(
                f"Missing {len(missing)} scheduled clients for round {server_round}. "
                f"Example missing cid={missing[0]}"
            )

        cfg: Dict[str, Scalar] = {}
        if self.on_fit_config_fn is not None:
            cfg = self.on_fit_config_fn(server_round)

        fit_ins = FitIns(parameters, cfg)
        
        return [(by_cid[cid], fit_ins) for cid in selected_cids]

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, FitRes]],
        failures: List[BaseException],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:
        # We always keep the model stable: on any issue, skip update and return current params.
        def _return_current(reason: str, extra: Dict[str, Scalar] | None = None):
            metrics: Dict[str, Scalar] = {"skipped": 1, "reason": reason}
            if extra:
                metrics.update(extra)

            # Return the current global model
            cur_params = ndarrays_to_parameters(self._unflatten_parameters(self._current_flat))
            return cur_params, metrics

        # 0) Failures mean the participant set likely differs from the TERSE schedule
        if failures:
            print(f"[round={server_round}] SKIPPING update: {len(failures)} failures, {len(results)} results")
            cur_params = ndarrays_to_parameters(self._unflatten_parameters(self._current_flat))
            return cur_params, {"skipped": 1, "num_failures": len(failures), "num_results": len(results)}


        if not results:
            return _return_current("no_results")

        # 1) Validate participant set exactly matches what configure_fit scheduled
        expected_cids = getattr(self, "_expected_cids_for_round", None)
        if not expected_cids:
            # If this happens, wire configure_fit to set self._expected_cids_for_round
            return _return_current("missing_expected_cids_for_round")

        expected_set = set(expected_cids)

        got_cids = [client.cid for client, _ in results]
        got_set = set(got_cids)

        if len(got_cids) != len(got_set):
            return _return_current("duplicate_client_in_results")

        if got_set != expected_set:
            return _return_current(
                "participant_mismatch",
                {
                    "expected_n": len(expected_set),
                    "got_n": len(got_set),
                },
            )

        if len(results) != len(expected_cids):
            # Same set but wrong count shouldn't happen; still skip (safe default)
            return _return_current(
                "participant_count_mismatch",
                {"expected_n": len(expected_cids), "got_n": len(results)},
            )

        # 2) Reorder results to match expected_cids (deterministic aggregation)
        by_cid: Dict[str, Tuple[ClientProxy, FitRes]] = {c.cid: (c, fr) for c, fr in results}
        ordered_results: List[Tuple[ClientProxy, FitRes]] = [by_cid[cid] for cid in expected_cids]

        # 3) Collect encrypted chunks; validate shapes/counts
        all_client_chunks: List[List[np.ndarray]] = []
        for client, fit_res in ordered_results:
            enc_chunks = parameters_to_ndarrays(fit_res.parameters)

            if len(enc_chunks) != self.n_chunks:
                return _return_current(
                    "client_wrong_num_chunks",
                    {"cid_len_mismatch": 1, "got_chunks": len(enc_chunks), "expected_chunks": self.n_chunks},
                )

            all_client_chunks.append(enc_chunks)

        start_ts = (server_round - 1) * self.n_chunks

        # 4) Aggregate and save encrypted aggregates for all chunks (untrusted)
        for chunk_idx in range(self.n_chunks):
            try:
                client_ciphertexts = [
                    np.ascontiguousarray(client_chunks[chunk_idx], dtype=np.uint64)
                    for client_chunks in all_client_chunks
                ]
            except Exception:
                return _return_current("ciphertext_cast_failed")

            timestamp = start_ts + chunk_idx
            try:
                aggregate_ct = self.terse_server.aggregate_ciphertexts(client_ciphertexts, timestamp)
                self.terse_server.save_aggregate(aggregate_ct, timestamp)
            except Exception:
                return _return_current("aggregate_or_save_failed")

        # 5) Trusted decrypt + DP; enclave writes decrypted_<ts>.bin
        try:
            self._enclave.decrypt_round(
                start_ts=start_ts,
                n_chunks=self.n_chunks,
                vector_dim=self.vector_dim,
                dp=self._enclave_dp,
            )
        except Exception:
            return _return_current("enclave_decrypt_round_failed")

        # 6) Load decrypted chunks, dequantize, average, stitch
        n_participants = len(ordered_results)
        aggregated_delta_flat = np.zeros(self.padded_len, dtype=np.float32)

        for chunk_idx in range(self.n_chunks):
            timestamp = start_ts + chunk_idx
            try:
                decrypted = self._load_decrypted_chunk(timestamp)
                chunk_float = dequantize_parameters(
                    decrypted,
                    self.scale_factor,
                    self.plaintext_modulus,
                ).astype(np.float32, copy=False)
            except Exception:
                return _return_current("load_or_dequantize_failed")

            if not np.all(np.isfinite(chunk_float)):
                return _return_current("nonfinite_dequantized_chunk")

            # post-processing average
            chunk_float = chunk_float / float(n_participants)

            start = chunk_idx * self.vector_dim
            end = start + self.vector_dim
            aggregated_delta_flat[start:end] = chunk_float

        aggregated_delta_flat = aggregated_delta_flat[: self.model_param_count]

        if not np.all(np.isfinite(aggregated_delta_flat)):
            return _return_current("nonfinite_aggregated_delta")

        # 7) Apply update (with rollback protection)
        prev_flat = self._current_flat.copy()
        self._current_flat = self._current_flat + aggregated_delta_flat

        if not np.all(np.isfinite(self._current_flat)):
            self._current_flat = prev_flat
            return _return_current("nonfinite_new_global_params")

        # 8) Optional: aggregate client-reported loss
        total_examples = 0
        weighted_loss = 0.0
        for _client, fit_res in ordered_results:
            num_ex = int(getattr(fit_res, "num_examples", 0) or 0)
            loss = fit_res.metrics.get("train_loss", None) if fit_res.metrics else None
            if loss is not None and num_ex > 0:
                total_examples += num_ex
                weighted_loss += float(loss) * num_ex

        metrics: Dict[str, Scalar] = {"skipped": 0, "num_clients": n_participants}
        if total_examples > 0:
            metrics["train_loss"] = weighted_loss / float(total_examples)

        new_params = self._unflatten_parameters(self._current_flat)
        return ndarrays_to_parameters(new_params), metrics


    def _unflatten_parameters(self, flat_params: np.ndarray) -> List[np.ndarray]:
        model = Net()
        params: List[np.ndarray] = []
        offset = 0

        for param in model.parameters():
            shape = param.shape
            numel = param.numel()
            param_flat = flat_params[offset : offset + numel]
            params.append(param_flat.reshape(shape))
            offset += numel

        return params


def get_evaluate_fn():
    def evaluate(server_round: int, parameters: List[np.ndarray], config: Dict[str, Scalar]):
        model = Net()

        params_dict = zip(model.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        model.load_state_dict(state_dict, strict=True)

        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        model.to(device)

        testloader = load_centralized_dataset()
        loss, accuracy = test(model, testloader, device)

        print(f"[Round {server_round}] Accuracy: {accuracy:.4f}, Loss: {loss:.4f}")
        return loss, {"accuracy": accuracy}

    return evaluate


def server_fn(context: Context) -> ServerAppComponents:
    os.chdir(PROJECT_ROOT)

    num_rounds = int(context.run_config["num-server-rounds"])
    n_clients = int(context.run_config["num-clients"])
    vector_dim = int(context.run_config["vector-dim"])
    scale_factor = int(context.run_config["scale-factor"])
    plaintext_modulus = int(context.run_config["plaintext-modulus"])

    fraction_evaluate = float(context.run_config.get("fraction-evaluate", 1.0))

    # fraction-fit drives schedule generation (trusted setup)
    fraction_fit = float(context.run_config.get("fraction-fit", 1.0))
    schedule_seed = context.run_config.get("schedule-seed", None)
    schedule_seed_int = int(schedule_seed) if schedule_seed is not None else None

    model = Net()
    model_param_count = count_parameters(model)

    padded_len = ((model_param_count + vector_dim - 1) // vector_dim) * vector_dim
    n_chunks = padded_len // vector_dim
    n_timestamps = num_rounds * n_chunks

    print(f"[TERSE Server] Model has {model_param_count} parameters")
    print(f"[TERSE Server] Using {n_chunks} chunks/round, {n_timestamps} total timestamps")
    print(f"[TERSE Server] fraction_fit={fraction_fit}, fraction_evaluate={fraction_evaluate}")

    # Generate artifacts + schedule + round-aware server_key.bin
    run_terse_setup_rounds(
        n_clients=n_clients,
        n_rounds=num_rounds,
        n_chunks=n_chunks,
        vector_dim=vector_dim,
        fraction_fit=fraction_fit,
        schedule_seed=schedule_seed_int,
    )

    def fit_config(server_round: int) -> Dict[str, Scalar]:
        return {"server_round": server_round}

    initial_nd = [v.detach().cpu().numpy() for v in model.state_dict().values()]
    initial_parameters = ndarrays_to_parameters(initial_nd)

    strategy = TERSEFedAvg(
        n_clients=n_clients,
        vector_dim=vector_dim,
        scale_factor=scale_factor,
        plaintext_modulus=plaintext_modulus,
        model_param_count=model_param_count,
        initial_parameters=initial_parameters,
        n_server_rounds=num_rounds,
        fraction_fit=1.0,
        fraction_evaluate=fraction_evaluate,
        evaluate_fn=get_evaluate_fn(),
        on_fit_config_fn=fit_config,
        accept_failures=False,
        min_fit_clients=1,
        min_available_clients=1,
    )

    return ServerAppComponents(
        strategy=strategy,
        config=ServerConfig(num_rounds=num_rounds),
    )


app = ServerApp(server_fn=server_fn)
