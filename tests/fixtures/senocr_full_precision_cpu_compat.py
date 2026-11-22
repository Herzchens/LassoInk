"""Opt-in hosted compatibility probe; this is not a provider adapter or quality test."""

from __future__ import annotations

import ctypes
import gc
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


REPOSITORY = "Herzchens/LassoInk"
ALLOWED_BRANCHES = frozenset(
    {
        "feat/benchmark-fidelity",
        "feat/benchmark-observability",
        "feat/benchmark-resources",
        "feat/experimental-convert",
    }
)
MODEL_REPOSITORY = "VietAlphaLabs/SenOCR-Vi"
MODEL_REVISION = "1e70dff4ef0429b0d88a2b873fb5d03300af1a41"
MODEL_INDEX_FILE = "model.safetensors.index.json"
MODEL_WEIGHT_SHARD = "model-00001-of-00001.safetensors"
MODEL_API_URL = (
    "https://huggingface.co/api/models/"
    f"{MODEL_REPOSITORY}/revision/{MODEL_REVISION}?blobs=true"
)
MODEL_RESOLVE_BASE = "https://huggingface.co/"
EXPECTED_PYTHON = (3, 13, 17)
EXPECTED_TORCH = "2.15.0+cpu"
EXPECTED_TRANSFORMERS = "5.23.0"
EXPECTED_PILLOW = "13.0.0"
EXPECTED_JINJA2 = "3.1.6"
LOADING_INFO_KEYS = (
    "missing_keys",
    "unexpected_keys",
    "mismatched_keys",
    "error_msgs",
)
MAX_API_BYTES = 1_000_000
MAX_INDEX_BYTES = 64 * 1024
MAX_TOTAL_MODEL_BYTES = 3_900_000_000
PRE_DOWNLOAD_DISK_RESERVE_BYTES = 2 * 1024**3
POST_DOWNLOAD_DISK_RESERVE_BYTES = 1 * 1024**3
MIN_AVAILABLE_MEMORY_BYTES = 10 * 1024**3
DOWNLOAD_DEADLINE_SECONDS = 40 * 60
DOWNLOAD_SOCKET_TIMEOUT_SECONDS = 30
MAX_GENERATION_SECONDS = 180
CHUNK_BYTES = 4 * 1024 * 1024
CURRENT_STAGE = "startup"

# Each non-LFS oid is the pinned Git blob SHA-1, not a published SHA-256.
# LFS objects have an explicit published SHA-256 in the first-party model tree.
MODEL_FILES: dict[str, tuple[int, str | None, str | None]] = {
    "added_tokens.json": (
        25_381,
        "6a2790e1462ecb007f9b92dfb00f594701462889",
        None,
    ),
    "chat_template.jinja": (
        1_474,
        "d8b8c271d7a7245d4937098f53aa372cff3dba70",
        None,
    ),
    "config.json": (
        2_059,
        "c54711466ae75457f8e57b909a49dae570bfa5c5",
        None,
    ),
    "generation_config.json": (
        133,
        "ba87d71b9881c1d52f0be4286fb63e381ce3febf",
        None,
    ),
    "model-00001-of-00001.safetensors": (
        3_834_433_136,
        None,
        "7eddf25b5fd85055ac559108d2e33e07146f8eaf82e8fc38cc434a49f4fb2ff1",
    ),
    "model.safetensors.index.json": (
        58_809,
        "2ff7eaa057e0b7cfe0d42e1189cc670c402a2c08",
        None,
    ),
    "preprocessor_config.json": (
        641,
        "d873cd63d04d9e6243999759fc30f7752dab3222",
        None,
    ),
    "processor_config.json": (
        137,
        "033053ac4d8b5de2e47884ce85a6b4939cc58e87",
        None,
    ),
    "special_tokens_map.json": (
        1_151,
        "dcd70aaa8c9987899d7593995546d9c0cfc6a1f3",
        None,
    ),
    "tokenizer.json": (
        11_189_060,
        None,
        "c8a215a59183d0d0781adc33bacd3ce6162716f7fd568fb30234a74d69803a7d",
    ),
    "tokenizer.model": (
        1_614_363,
        None,
        "34ef7db83df785924fb83d7b887b6e822a031c56e15cff40aaf9b982988180df",
    ),
    "tokenizer_config.json": (
        186_947,
        "cd9eb7da01a3209f4fb9b3561e04be022cd87764",
        None,
    ),
}


class ProbeFailure(Exception):
    """A sanitized, bounded failure reason safe for the hosted log."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ProbeFailure(reason)


def guard_execution_context() -> None:
    require(os.name == "nt", "windows_required")
    require(platform.machine().lower() in {"amd64", "x86_64"}, "x64_required")
    require(os.environ.get("CI", "").lower() == "true", "ci_required")
    require(os.environ.get("GITHUB_ACTIONS", "").lower() == "true", "actions_required")
    require(
        os.environ.get("RUNNER_ENVIRONMENT", "") == "github-hosted",
        "github_hosted_runner_required",
    )
    require(os.environ.get("RUNNER_OS", "") == "Windows", "windows_runner_required")
    require(os.environ.get("RUNNER_ARCH", "") == "X64", "x64_runner_required")
    require(
        os.environ.get("GITHUB_REPOSITORY", "") == REPOSITORY
        and os.environ.get("EXPECTED_REPOSITORY", "") == REPOSITORY,
        "repository_guard_failed",
    )
    require(
        os.environ.get("LASSOINK_RUN_SENOCR_CPU_COMPAT", "") == "1",
        "explicit_opt_in_required",
    )
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    require(event_name == "pull_request", "pull_request_event_required")
    require(os.environ.get("EXPECTED_EVENT", "") == event_name, "event_context_mismatch")
    expected_head_ref = os.environ.get("EXPECTED_HEAD_REF", "")
    require(
        os.environ.get("EXPECTED_HEAD_REPOSITORY", "") == REPOSITORY
        and expected_head_ref in ALLOWED_BRANCHES
        and os.environ.get("GITHUB_HEAD_REF", "") == expected_head_ref,
        "pull_request_source_guard_failed",
    )

    expected_sha = os.environ.get("EXPECTED_HEAD_SHA", "")
    require(len(expected_sha) == 40 and all(c in "0123456789abcdef" for c in expected_sha), "expected_sha_invalid")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir(), "workspace_unavailable")
    try:
        actual_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise ProbeFailure("exact_head_check_failed") from None
    require(actual_sha == expected_sha, "exact_head_mismatch")


class HfRedirectHandler(HTTPRedirectHandler):
    """Permit HTTPS redirects only within Hugging Face-owned host suffixes."""

    @staticmethod
    def validate_url(url: str) -> None:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        allowed_host = (
            host == "huggingface.co"
            or host.endswith(".huggingface.co")
            or host == "hf.co"
            or host.endswith(".hf.co")
        )
        require(
            parsed.scheme == "https"
            and allowed_host
            and parsed.port in {None, 443}
            and parsed.username is None
            and parsed.password is None,
            "model_host_guard_failed",
        )

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        self.validate_url(new_url)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def make_opener():
    return build_opener(HfRedirectHandler())


def read_bounded_json(url: str) -> dict:
    HfRedirectHandler.validate_url(url)
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "LassoInk-raster-cpu-compat/1",
        },
        method="GET",
    )
    try:
        with make_opener().open(request, timeout=20) as response:
            HfRedirectHandler.validate_url(response.geturl())
            length = response.headers.get("Content-Length")
            if length is not None:
                require(length.isdecimal() and int(length) <= MAX_API_BYTES, "model_metadata_oversize")
            body = response.read(MAX_API_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError):
        raise ProbeFailure("model_metadata_unavailable") from None
    require(len(body) <= MAX_API_BYTES, "model_metadata_oversize")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProbeFailure("model_metadata_invalid") from None
    require(isinstance(value, dict), "model_metadata_invalid")
    return value


def git_blob_sha1(path: Path, size: int) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {size}\0".encode("ascii"))
    with path.open("rb") as stream:
        while block := stream.read(CHUNK_BYTES):
            digest.update(block)
    return digest.hexdigest()


def inspect_revision_metadata() -> dict[str, dict[str, object]]:
    metadata = read_bounded_json(MODEL_API_URL)
    require(metadata.get("id") == MODEL_REPOSITORY, "model_repository_mismatch")
    require(metadata.get("sha") == MODEL_REVISION, "model_revision_mismatch")
    require(metadata.get("private") is False, "model_repository_not_public")
    require(metadata.get("gated") is False, "model_repository_gated")
    require(metadata.get("disabled") is False, "model_repository_disabled")
    siblings = metadata.get("siblings")
    require(isinstance(siblings, list) and 0 < len(siblings) <= 64, "model_file_manifest_invalid")

    by_name: dict[str, dict[str, object]] = {}
    for sibling in siblings:
        if not isinstance(sibling, dict):
            raise ProbeFailure("model_file_manifest_invalid")
        name = sibling.get("rfilename")
        require(isinstance(name, str) and name not in by_name, "model_file_manifest_invalid")
        by_name[name] = sibling

    for name, (expected_size, expected_git_oid, expected_lfs_sha256) in MODEL_FILES.items():
        sibling = by_name.get(name)
        require(sibling is not None, "allowlisted_model_file_missing")
        require(sibling.get("size") == expected_size, "model_file_size_mismatch")
        require(sibling.get("blobId") == expected_git_oid if expected_git_oid else True, "model_git_oid_mismatch")
        lfs = sibling.get("lfs")
        if expected_lfs_sha256:
            require(isinstance(lfs, dict), "model_lfs_metadata_missing")
            require(lfs.get("sha256") == expected_lfs_sha256, "model_lfs_sha256_mismatch")
            require(lfs.get("size") == expected_size, "model_lfs_size_mismatch")
        else:
            require(lfs is None, "unexpected_lfs_metadata")
    return by_name


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "duplicate_safetensors_index_key")
        result[key] = value
    return result


def validate_safetensors_index_payload(payload: bytes) -> int:
    require(0 < len(payload) <= MAX_INDEX_BYTES, "safetensors_index_size_invalid")
    try:
        index_document = json.loads(payload, object_pairs_hook=_unique_json_object)
    except ProbeFailure:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProbeFailure("safetensors_index_invalid") from None
    require(isinstance(index_document, dict), "safetensors_index_invalid")
    weight_map = index_document.get("weight_map")
    require(isinstance(weight_map, dict) and 0 < len(weight_map) <= 10_000, "safetensors_weight_map_invalid")

    shard_names: set[str] = set()
    for tensor_name, shard_name in weight_map.items():
        require(isinstance(tensor_name, str) and tensor_name != "", "safetensors_tensor_name_invalid")
        require(isinstance(shard_name, str) and shard_name != "", "safetensors_shard_name_invalid")
        require("/" not in shard_name and "\\" not in shard_name, "safetensors_shard_path_rejected")
        require(shard_name in MODEL_FILES, "safetensors_shard_not_allowlisted")
        require(shard_name == MODEL_WEIGHT_SHARD, "safetensors_shard_mismatch")
        shard_names.add(shard_name)

    # Repeated weight-map values are expected for tensors in the one shard;
    # the set must nevertheless resolve to exactly that single allowlisted file.
    require(shard_names == {MODEL_WEIGHT_SHARD}, "safetensors_shard_set_mismatch")
    return len(weight_map)


def validate_safetensors_index_policy() -> None:
    valid_payload = (
        b'{"weight_map":{"layer.0.weight":"model-00001-of-00001.safetensors",'
        b'"layer.0.bias":"model-00001-of-00001.safetensors"}}'
    )
    require(validate_safetensors_index_payload(valid_payload) == 2, "safetensors_index_self_check_failed")
    rejected_payloads = (
        b"{}",
        b'{"weight_map":{}}',
        b'{"weight_map":{"layer":"folder/model-00001-of-00001.safetensors"}}',
        b'{"weight_map":{"layer":"model-00002-of-00001.safetensors"}}',
        b'{"weight_map":{"layer":"model-00001-of-00001.safetensors",'
        b'"layer":"model-00001-of-00001.safetensors"}}',
    )
    for payload in rejected_payloads:
        try:
            validate_safetensors_index_payload(payload)
        except ProbeFailure:
            continue
        raise ProbeFailure("safetensors_index_self_check_failed")


def validate_loading_info(loading_info: object) -> dict[str, int]:
    require(isinstance(loading_info, dict), "loading_info_missing")
    require(set(loading_info.keys()) == set(LOADING_INFO_KEYS), "loading_info_keys_invalid")
    require(isinstance(loading_info["missing_keys"], set), "loading_info_type_invalid")
    require(isinstance(loading_info["unexpected_keys"], set), "loading_info_type_invalid")
    require(isinstance(loading_info["mismatched_keys"], set), "loading_info_type_invalid")
    require(isinstance(loading_info["error_msgs"], list), "loading_info_type_invalid")

    counts = {key: len(loading_info[key]) for key in LOADING_INFO_KEYS}
    if any(counts.values()):
        raise ProbeFailure(
            "state_dict_key_mismatch_"
            f"missing_{counts['missing_keys']}_unexpected_{counts['unexpected_keys']}_"
            f"mismatched_{counts['mismatched_keys']}_errors_{counts['error_msgs']}"
        )
    return counts


def validate_loading_info_policy() -> None:
    zero_diagnostics = {
        "missing_keys": set(),
        "unexpected_keys": set(),
        "mismatched_keys": set(),
        "error_msgs": [],
    }
    require(
        validate_loading_info(zero_diagnostics)
        == {key: 0 for key in LOADING_INFO_KEYS},
        "loading_info_self_check_failed",
    )

    malformed_diagnostics = []
    for missing_key in LOADING_INFO_KEYS:
        malformed_diagnostics.append(
            {key: value for key, value in zero_diagnostics.items() if key != missing_key}
        )
    malformed_diagnostics.append(
        {
            **zero_diagnostics,
            "missing_keys": [],
        }
    )
    malformed_diagnostics.append(
        {
            **zero_diagnostics,
            "unexpected_keys": [],
        }
    )
    malformed_diagnostics.append(
        {
            **zero_diagnostics,
            "mismatched_keys": [],
        }
    )
    malformed_diagnostics.append(
        {
            **zero_diagnostics,
            "error_msgs": set(),
        }
    )
    malformed_diagnostics.append({**zero_diagnostics, "extra": []})
    for diagnostics in malformed_diagnostics:
        try:
            validate_loading_info(diagnostics)
        except ProbeFailure:
            continue
        raise ProbeFailure("loading_info_self_check_failed")

    nonzero_diagnostics = (
        ("missing_keys", {"sentinel"}),
        ("unexpected_keys", {"sentinel"}),
        ("mismatched_keys", {("sentinel", (1,), (2,))}),
        ("error_msgs", ["sentinel"]),
    )
    for category, value in nonzero_diagnostics:
        diagnostics = {**zero_diagnostics, category: value}
        try:
            validate_loading_info(diagnostics)
        except ProbeFailure as error:
            require(
                isinstance(error.args[0], str)
                and error.args[0].startswith("state_dict_key_mismatch_"),
                "loading_info_self_check_failed",
            )
            continue
        raise ProbeFailure("loading_info_self_check_failed")


def download_one_file(model_dir: Path, name: str, deadline: float, already_downloaded: int) -> dict[str, object]:
    expected_size, expected_git_oid, expected_lfs_sha256 = MODEL_FILES[name]
    require(Path(name).name == name and "/" not in name and "\\" not in name, "unsafe_model_filename")
    destination = model_dir / name
    url = f"{MODEL_RESOLVE_BASE}{MODEL_REPOSITORY}/resolve/{MODEL_REVISION}/{quote(name)}?download=true"
    request = Request(
        url,
        headers={
            "Accept-Encoding": "identity",
            "User-Agent": "LassoInk-raster-cpu-compat/1",
        },
        method="GET",
    )
    HfRedirectHandler.validate_url(url)
    downloaded = 0
    sha256 = hashlib.sha256() if expected_lfs_sha256 else None
    sha1 = hashlib.sha1() if expected_git_oid else None
    if sha1 is not None:
        sha1.update(f"blob {expected_size}\0".encode("ascii"))
    try:
        with make_opener().open(request, timeout=DOWNLOAD_SOCKET_TIMEOUT_SECONDS) as response:
            HfRedirectHandler.validate_url(response.geturl())
            require(response.status == 200, "model_file_http_status")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                require(content_length.isdecimal() and int(content_length) == expected_size, "model_file_content_length_mismatch")
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            require(encoding in {"", "identity"}, "unexpected_model_content_encoding")
            with destination.open("xb") as output:
                while block := response.read(CHUNK_BYTES):
                    require(time.monotonic() <= deadline, "model_download_deadline")
                    downloaded += len(block)
                    require(downloaded <= expected_size, "model_file_oversize")
                    require(already_downloaded + downloaded <= MAX_TOTAL_MODEL_BYTES, "model_total_oversize")
                    output.write(block)
                    if sha256 is not None:
                        sha256.update(block)
                    if sha1 is not None:
                        sha1.update(block)
    except ProbeFailure:
        raise
    except (HTTPError, URLError, TimeoutError, OSError):
        raise ProbeFailure("model_file_download_failed") from None

    require(downloaded == expected_size, "model_file_truncated")
    actual_sha256 = sha256.hexdigest() if sha256 is not None else None
    actual_git_oid = sha1.hexdigest() if sha1 is not None else None
    require(actual_sha256 == expected_lfs_sha256 if expected_lfs_sha256 else True, "model_file_sha256_mismatch")
    require(actual_git_oid == expected_git_oid if expected_git_oid else True, "model_file_git_oid_mismatch")
    return {
        "name": name,
        "bytes": downloaded,
        "digest_kind": "sha256" if actual_sha256 else "git_blob_sha1",
        "digest": actual_sha256 or actual_git_oid,
    }


def available_physical_memory_bytes() -> int:
    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(status)
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        function = kernel32.GlobalMemoryStatusEx
        function.argtypes = [ctypes.POINTER(MemoryStatusEx)]
        function.restype = ctypes.c_int32
        require(function(ctypes.byref(status)), "memory_probe_failed")
    except (AttributeError, OSError):
        raise ProbeFailure("memory_probe_failed") from None
    return int(status.ullAvailPhys)


def require_resources(temp_root: Path, minimum_free_disk_bytes: int) -> None:
    free_disk_bytes = shutil.disk_usage(temp_root).free
    if free_disk_bytes < minimum_free_disk_bytes:
        raise ProbeFailure(
            f"insufficient_free_disk_required_{minimum_free_disk_bytes}_available_{free_disk_bytes}"
        )
    available_memory_bytes = available_physical_memory_bytes()
    if available_memory_bytes < MIN_AVAILABLE_MEMORY_BYTES:
        raise ProbeFailure(
            "insufficient_available_memory_required_"
            f"{MIN_AVAILABLE_MEMORY_BYTES}_available_{available_memory_bytes}"
        )


def checked_dependency_versions() -> dict[str, str]:
    require(sys.version_info[:3] == EXPECTED_PYTHON, "python_version_mismatch")
    try:
        import torch
        import transformers
        from PIL import Image
    except Exception as error:
        raise ProbeFailure(f"runtime_import_failed_{type(error).__name__}") from None

    versions = {
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        "torch": str(torch.__version__),
        "transformers": str(transformers.__version__),
        "Pillow": importlib.metadata.version("Pillow"),
        "Jinja2": importlib.metadata.version("Jinja2"),
        "huggingface-hub": importlib.metadata.version("huggingface-hub"),
        "safetensors": importlib.metadata.version("safetensors"),
        "tokenizers": importlib.metadata.version("tokenizers"),
        "numpy": importlib.metadata.version("numpy"),
    }
    require(versions["torch"] == EXPECTED_TORCH, "torch_version_or_cpu_build_mismatch")
    require(versions["transformers"] == EXPECTED_TRANSFORMERS, "transformers_version_mismatch")
    require(versions["Pillow"] == EXPECTED_PILLOW, "pillow_version_mismatch")
    require(versions["Jinja2"] == EXPECTED_JINJA2, "jinja2_version_mismatch")
    require(torch.version.cuda is None, "non_cpu_torch_build")
    torch.set_num_threads(2)
    torch.set_num_interop_threads(1)
    return versions


def run_probe() -> dict[str, object]:
    global CURRENT_STAGE
    CURRENT_STAGE = "safetensors_index_policy_self_check"
    validate_safetensors_index_policy()
    CURRENT_STAGE = "loading_info_policy_self_check"
    validate_loading_info_policy()

    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    require(runner_temp.is_absolute() and runner_temp.is_dir(), "runner_temp_unavailable")

    CURRENT_STAGE = "temporary_workspace"
    with tempfile.TemporaryDirectory(prefix="lasso-senocr-compat-", dir=runner_temp) as temporary_directory:
        temporary_root = Path(temporary_directory).resolve()
        keep_assets_for_worker_e2e = (
            os.environ.get("LASSOINK_RUN_SENOCR_M4_E2E") == "1"
        )
        if keep_assets_for_worker_e2e:
            model_dir = Path(os.environ.get("LASSOINK_SENOCR_ASSET_ROOT", ""))
            require(
                model_dir.is_absolute()
                and model_dir.name == "lasso-senocr-worker-assets"
                and model_dir.parent.resolve() == runner_temp.resolve()
                and not model_dir.exists()
                and not model_dir.is_symlink(),
                "worker_asset_temp_path_invalid",
            )
        else:
            model_dir = temporary_root / "model"
        expected_total_bytes = sum(value[0] for value in MODEL_FILES.values())
        require(expected_total_bytes <= MAX_TOTAL_MODEL_BYTES, "manifest_total_oversize")
        pre_download_free_disk = expected_total_bytes + PRE_DOWNLOAD_DISK_RESERVE_BYTES
        require_resources(temporary_root, pre_download_free_disk)

        os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
        os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        os.environ["TOKENIZERS_PARALLELISM"] = "false"
        os.environ["OMP_NUM_THREADS"] = "2"
        os.environ["MKL_NUM_THREADS"] = "2"
        os.environ["OPENBLAS_NUM_THREADS"] = "1"
        os.environ["TMP"] = str(temporary_root)
        os.environ["TEMP"] = str(temporary_root)
        os.environ["HF_HOME"] = str(temporary_root / "hf-home")
        os.environ["TORCH_HOME"] = str(temporary_root / "torch-home")

        CURRENT_STAGE = "runtime_versions"
        versions = checked_dependency_versions()
        require_resources(temporary_root, pre_download_free_disk)

        CURRENT_STAGE = "model_revision_metadata"
        metadata_started = time.perf_counter()
        repository_files = inspect_revision_metadata()
        metadata_elapsed_ms = int((time.perf_counter() - metadata_started) * 1000)
        require_resources(temporary_root, pre_download_free_disk)

        model_dir.mkdir()
        download_started = time.perf_counter()
        download_deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
        downloaded_files: list[dict[str, object]] = []
        total_bytes = 0
        metadata_files = [name for name in MODEL_FILES if name != MODEL_WEIGHT_SHARD]
        CURRENT_STAGE = "model_metadata_file_download"
        for name in metadata_files:
            require(name in repository_files, "allowlisted_model_file_missing")
            downloaded = download_one_file(model_dir, name, download_deadline, total_bytes)
            total_bytes += int(downloaded["bytes"])
            downloaded_files.append(downloaded)

        CURRENT_STAGE = "metadata_allowlist_validation"
        actual_names = {path.name for path in model_dir.iterdir()}
        require(
            actual_names == set(MODEL_FILES) - {MODEL_WEIGHT_SHARD},
            "downloaded_metadata_allowlist_mismatch",
        )
        for path in model_dir.iterdir():
            require(path.is_file() and not path.is_symlink(), "unexpected_model_file_type")
            require(path.suffix.lower() not in {".py", ".pth", ".pt", ".bin", ".pickle", ".pkl"}, "unsafe_model_artifact_present")

        CURRENT_STAGE = "safetensors_index_validation"
        index_path = model_dir / MODEL_INDEX_FILE
        require(index_path.stat().st_size <= MAX_INDEX_BYTES, "safetensors_index_size_invalid")
        with index_path.open("rb") as index_stream:
            index_payload = index_stream.read(MAX_INDEX_BYTES + 1)
        indexed_tensor_count = validate_safetensors_index_payload(index_payload)

        CURRENT_STAGE = "model_weight_download"
        weight_file = download_one_file(
            model_dir,
            MODEL_WEIGHT_SHARD,
            download_deadline,
            total_bytes,
        )
        total_bytes += int(weight_file["bytes"])
        downloaded_files.append(weight_file)
        require(total_bytes == expected_total_bytes, "model_total_size_mismatch")
        require(
            {path.name for path in model_dir.iterdir()} == set(MODEL_FILES),
            "downloaded_file_allowlist_mismatch",
        )
        require_resources(temporary_root, POST_DOWNLOAD_DISK_RESERVE_BYTES)

        CURRENT_STAGE = "model_load"
        import torch
        from PIL import Image
        from transformers import AutoProcessor
        from transformers.models.paddleocr_vl.modeling_paddleocr_vl import (
            PaddleOCRVLForConditionalGeneration,
        )

        model_load_started = time.perf_counter()
        processor = AutoProcessor.from_pretrained(
            model_dir,
            local_files_only=True,
            trust_remote_code=False,
        )
        model, loading_info = PaddleOCRVLForConditionalGeneration.from_pretrained(
            model_dir,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
            dtype=torch.float32,
            attn_implementation="eager",
            ignore_mismatched_sizes=False,
            output_loading_info=True,
        )
        loading_info_counts = validate_loading_info(loading_info)
        require(
            model.__class__.__module__.startswith("transformers.models.paddleocr_vl."),
            "non_builtin_model_class",
        )
        require(
            processor.__class__.__module__.startswith("transformers.models.paddleocr_vl."),
            "non_builtin_processor_class",
        )
        model.to("cpu")
        model.eval()
        first_parameter = next(model.parameters(), None)
        require(first_parameter is not None, "model_has_no_parameters")
        require(first_parameter.device.type == "cpu", "model_not_on_cpu")
        require(first_parameter.dtype == torch.float32, "model_not_fp32")
        require(
            all(
                parameter.device.type == "cpu" and parameter.dtype == torch.float32
                for parameter in model.parameters()
            ),
            "model_parameters_not_cpu_fp32",
        )
        model_load_elapsed_ms = int((time.perf_counter() - model_load_started) * 1000)

        CURRENT_STAGE = "synthetic_single_token_generate"
        image = Image.new("RGB", (384, 384), (255, 255, 255))
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "image", "image": image},
                    {"type": "text", "text": "OCR:"},
                ],
            }
        ]
        inputs = processor.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        ).to("cpu")
        input_token_count = int(inputs["input_ids"].shape[-1])
        generation_started = time.perf_counter()
        with torch.inference_mode():
            generated = model.generate(
                **inputs,
                max_new_tokens=1,
                max_time=90.0,
                do_sample=False,
                num_beams=1,
                use_cache=False,
            )
        generation_elapsed_ms = int((time.perf_counter() - generation_started) * 1000)
        require(generation_elapsed_ms <= MAX_GENERATION_SECONDS * 1000, "synthetic_generation_deadline")
        require(generated.ndim == 2 and generated.shape[0] == 1, "synthetic_generation_shape_invalid")
        generated_token_count = int(generated.shape[-1]) - input_token_count
        require(generated_token_count == 1, "synthetic_generation_token_bound_failed")

        result: dict[str, object] = {
            "status": "compatibility_pass",
            "scope": "synthetic_blank_image_one_token_cpu_only",
            "quality_or_selection_claim": False,
            "model_repository": MODEL_REPOSITORY,
            "model_revision": MODEL_REVISION,
            "model_weight_sha256": MODEL_FILES[MODEL_WEIGHT_SHARD][2],
            "dependencies": versions,
            "downloaded_file_count": len(downloaded_files),
            "downloaded_bytes": total_bytes,
            "indexed_tensor_count": indexed_tensor_count,
            "downloaded_manifest": downloaded_files,
            "loading_info_counts": loading_info_counts,
            "input_tokens": input_token_count,
            "generated_tokens": generated_token_count,
            "metadata_elapsed_ms": metadata_elapsed_ms,
            "download_elapsed_ms": int((time.perf_counter() - download_started) * 1000),
            "model_load_elapsed_ms": model_load_elapsed_ms,
            "one_token_generate_elapsed_ms": generation_elapsed_ms,
        }

        generated = None
        inputs = None
        image = None
        model = None
        processor = None
        gc.collect()
        return result


def main() -> int:
    global CURRENT_STAGE
    try:
        guard_execution_context()
        CURRENT_STAGE = "probe"
        result = run_probe()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except ProbeFailure as error:
        print(
            json.dumps(
                {"status": "failed", "stage": CURRENT_STAGE, "reason": error.args[0]},
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        return 1
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "stage": CURRENT_STAGE,
                    "error_type": type(error).__name__,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
