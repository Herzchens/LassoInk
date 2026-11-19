"""Optional BYO-local SenOCR-Vi FP32 Raster worker.

Only standard-library imports and the M4 framing frontend are eager. Pillow,
PyTorch, and Transformers load lazily after config, asset, resource, and full PNG
decode checks. This module makes no network-isolation, parity, or quality claim.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import io
import json
import logging
import os
import platform
import shutil
import stat
import sys
import tempfile
import time
import zlib
from pathlib import Path, PureWindowsPath
from typing import BinaryIO, Callable

# When invoked as an absolute script path, Python puts only this file's
# directory on sys.path. Resolve the trusted sibling package from __file__, not
# the caller's working directory or project metadata.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import raster_reference_protocol as protocol
from tools import senocr_runtime_profile as runtime_profile


MODEL_REPOSITORY = "VietAlphaLabs/SenOCR-Vi"
MODEL_REVISION = "1e70dff4ef0429b0d88a2b873fb5d03300af1a41"
MODEL_INDEX_FILE = "model.safetensors.index.json"
MODEL_WEIGHT_SHARD = "model-00001-of-00001.safetensors"
MODEL_FILES: dict[str, tuple[int, str | None, str | None]] = {
    "added_tokens.json": (25_381, "6a2790e1462ecb007f9b92dfb00f594701462889", None),
    "chat_template.jinja": (1_474, "d8b8c271d7a7245d4937098f53aa372cff3dba70", None),
    "config.json": (2_059, "c54711466ae75457f8e57b909a49dae570bfa5c5", None),
    "generation_config.json": (133, "ba87d71b9881c1d52f0be4286fb63e381ce3febf", None),
    MODEL_WEIGHT_SHARD: (
        3_834_433_136,
        None,
        "7eddf25b5fd85055ac559108d2e33e07146f8eaf82e8fc38cc434a49f4fb2ff1",
    ),
    MODEL_INDEX_FILE: (58_809, "2ff7eaa057e0b7cfe0d42e1189cc670c402a2c08", None),
    "preprocessor_config.json": (641, "d873cd63d04d9e6243999759fc30f7752dab3222", None),
    "processor_config.json": (137, "033053ac4d8b5de2e47884ce85a6b4939cc58e87", None),
    "special_tokens_map.json": (1_151, "dcd70aaa8c9987899d7593995546d9c0cfc6a1f3", None),
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
    "tokenizer_config.json": (186_947, "cd9eb7da01a3209f4fb9b3561e04be022cd87764", None),
}

EXPECTED_PROVIDER_CONFIGURATION_ID = "senocr-v1-fp32-local"
EXPECTED_PROVIDER_CONFIGURATION_KEYS = {"model_id", "model_revision", "asset_root"}
MAX_TOTAL_MODEL_BYTES = 3_900_000_000
MAX_INDEX_BYTES = 64 * 1024
HASH_CHUNK_BYTES = 4 * 1024 * 1024
MAX_HASH_SECONDS = 100
MIN_AVAILABLE_MEMORY_BYTES = 10 * 1024**3
MIN_TEMP_DISK_BYTES = 1 * 1024**3
MAX_GENERATION_SECONDS = 90
MAX_GENERATED_TOKENS = 256
MAX_E2E_PROCESSOR_TENSOR_BYTES = 32 * 1024 * 1024
MAX_E2E_SIDECAR_BYTES = 16 * 1024
MAX_RASTER_PIXELS = protocol.MAX_TOTAL_RAW_SAMPLE_BYTES
MAX_RASTER_BYTES = protocol.MAX_RASTER_INPUT_BYTES
EXPECTED_PYTHON = tuple(
    int(part) for part in runtime_profile.EXPECTED_PYTHON_VERSION.split(".")
)

SENOCR_PROVIDER_IDENTITY: dict[str, object] = {
    "provider_id": "senocr-v1-fp32-local",
    "provider_version": "stdlib-senocr-fp32-worker-v1",
    "model_version": MODEL_REVISION,
    # This identifies only the declared runtime package profile; it is not a
    # wheel-authenticity or loaded-file-integrity assertion.
    "resource_version": f"senocr-runtime-profile-v1-sha256-{runtime_profile.PROFILE_SHA256}",
}
SENOCR_CAPABILITIES: dict[str, object] = {
    "inputs": ["raster"],
    "outputs": ["text"],
    "languages": ["vi-VN"],
}
SENOCR_PROVIDER_PROVENANCE = (
    f"{MODEL_REPOSITORY}@{MODEL_REVISION}; full-precision; built-in CPU runtime; "
    f"runtime-profile-v1-sha256={runtime_profile.PROFILE_SHA256}"
)


def validate_senocr_provider_configuration(configuration: object) -> Path:
    """Read only the exact model keys from the already verified M4 request."""
    try:
        validated = protocol.validate_provider_configuration(configuration)
    except protocol.ProtocolError:
        raise protocol.WorkerFailure("invalid_provider_configuration") from None
    if validated["configuration_id"] != EXPECTED_PROVIDER_CONFIGURATION_ID:
        raise protocol.WorkerFailure("invalid_provider_configuration")
    values = validated["values"]
    if type(values) is not dict or set(values) != EXPECTED_PROVIDER_CONFIGURATION_KEYS:
        raise protocol.WorkerFailure("invalid_provider_configuration")
    if values["model_id"] != MODEL_REPOSITORY or values["model_revision"] != MODEL_REVISION:
        raise protocol.WorkerFailure("unsupported_model_revision")
    asset_root = values["asset_root"]
    if type(asset_root) is not str or any(ord(character) < 0x20 for character in asset_root):
        raise protocol.WorkerFailure("invalid_provider_configuration")
    windows_path = PureWindowsPath(asset_root)
    if (
        not windows_path.is_absolute()
        or asset_root.startswith(("\\\\", "//"))
        or ".." in windows_path.parts
        or len(asset_root.encode("utf-8")) > protocol.MAX_SETTING_VALUE_BYTES
    ):
        raise protocol.WorkerFailure("invalid_provider_configuration")
    return Path(asset_root)


def validate_asset_inventory_names(names: object) -> None:
    if not isinstance(names, (set, frozenset)) or names != set(MODEL_FILES):
        raise protocol.WorkerFailure("asset_inventory_mismatch")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise protocol.WorkerFailure("safetensors_index_invalid")
        result[key] = value
    return result


def validate_safetensors_index_payload(payload: bytes) -> int:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_INDEX_BYTES:
        raise protocol.WorkerFailure("safetensors_index_invalid")
    try:
        document = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except protocol.WorkerFailure:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise protocol.WorkerFailure("safetensors_index_invalid") from None
    if type(document) is not dict:
        raise protocol.WorkerFailure("safetensors_index_invalid")
    weight_map = document.get("weight_map")
    if type(weight_map) is not dict or not 0 < len(weight_map) <= 10_000:
        raise protocol.WorkerFailure("safetensors_index_invalid")
    for tensor_name, shard_name in weight_map.items():
        if (
            type(tensor_name) is not str
            or not tensor_name
            or type(shard_name) is not str
            or shard_name != MODEL_WEIGHT_SHARD
            or "/" in shard_name
            or "\\" in shard_name
        ):
            raise protocol.WorkerFailure("safetensors_index_invalid")
    return len(weight_map)


def hash_asset_stream(
    stream: BinaryIO,
    expected_size: int,
    *,
    git_blob_sha1: bool,
    deadline: float | None = None,
) -> str:
    if type(expected_size) is not int or not 0 <= expected_size <= MAX_TOTAL_MODEL_BYTES:
        raise protocol.WorkerFailure("asset_inventory_mismatch")
    digest = hashlib.sha1() if git_blob_sha1 else hashlib.sha256()
    if git_blob_sha1:
        digest.update(f"blob {expected_size}\0".encode("ascii"))
    total = 0
    while True:
        if deadline is not None and time.monotonic() > deadline:
            raise protocol.WorkerFailure("asset_read_failed")
        try:
            block = stream.read(HASH_CHUNK_BYTES)
        except OSError:
            raise protocol.WorkerFailure("asset_read_failed") from None
        if not block:
            break
        total += len(block)
        if total > expected_size or total > MAX_TOTAL_MODEL_BYTES:
            raise protocol.WorkerFailure("asset_inventory_mismatch")
        digest.update(block)
    if total != expected_size:
        raise protocol.WorkerFailure("asset_inventory_mismatch")
    return digest.hexdigest()


def _has_reparse_attribute(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction is not None and is_junction():
            return True
        metadata = path.lstat()
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _has_reparse_in_path(path: Path) -> bool:
    return any(_has_reparse_attribute(component) for component in (path, *path.parents))


def verify_senocr_asset_directory(asset_root: Path) -> None:
    if not asset_root.is_absolute() or _has_reparse_in_path(asset_root):
        raise protocol.WorkerFailure("asset_directory_invalid")
    try:
        if not asset_root.is_dir():
            raise protocol.WorkerFailure("asset_directory_invalid")
        entries = []
        for entry in asset_root.iterdir():
            entries.append(entry)
            if len(entries) > len(MODEL_FILES):
                raise protocol.WorkerFailure("asset_inventory_mismatch")
    except protocol.WorkerFailure:
        raise
    except OSError:
        raise protocol.WorkerFailure("asset_directory_invalid") from None
    validate_asset_inventory_names({entry.name for entry in entries})

    expected_total = sum(spec[0] for spec in MODEL_FILES.values())
    if expected_total > MAX_TOTAL_MODEL_BYTES:
        raise protocol.WorkerFailure("asset_inventory_mismatch")
    deadline = time.monotonic() + MAX_HASH_SECONDS
    for name, (expected_size, expected_git_oid, expected_lfs_sha256) in MODEL_FILES.items():
        path = asset_root / name
        if _has_reparse_attribute(path):
            raise protocol.WorkerFailure("asset_inventory_mismatch")
        try:
            before_path = path.lstat()
            if not stat.S_ISREG(before_path.st_mode) or before_path.st_size != expected_size:
                raise protocol.WorkerFailure("asset_inventory_mismatch")
            with path.open("rb") as stream:
                before_handle = os.fstat(stream.fileno())
                if not stat.S_ISREG(before_handle.st_mode) or before_handle.st_size != expected_size:
                    raise protocol.WorkerFailure("asset_inventory_mismatch")
                digest = hash_asset_stream(
                    stream,
                    expected_size,
                    git_blob_sha1=expected_git_oid is not None,
                    deadline=deadline,
                )
                after_handle = os.fstat(stream.fileno())
            after_path = path.lstat()
        except protocol.WorkerFailure:
            raise
        except OSError:
            raise protocol.WorkerFailure("asset_read_failed") from None
        if (
            after_handle.st_size != expected_size
            or after_path.st_size != expected_size
            or _has_reparse_attribute(path)
        ):
            raise protocol.WorkerFailure("asset_inventory_mismatch")
        expected_digest = expected_git_oid or expected_lfs_sha256
        if digest != expected_digest:
            raise protocol.WorkerFailure("asset_hash_mismatch")

    index_path = asset_root / MODEL_INDEX_FILE
    try:
        if _has_reparse_attribute(index_path) or index_path.stat().st_size > MAX_INDEX_BYTES:
            raise protocol.WorkerFailure("safetensors_index_invalid")
        with index_path.open("rb") as stream:
            index_payload = stream.read(MAX_INDEX_BYTES + 1)
    except protocol.WorkerFailure:
        raise
    except OSError:
        raise protocol.WorkerFailure("safetensors_index_invalid") from None
    validate_safetensors_index_payload(index_payload)


def _available_physical_memory_bytes() -> int:
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
        if not function(ctypes.byref(status)):
            raise protocol.WorkerFailure("insufficient_memory")
    except protocol.WorkerFailure:
        raise
    except (AttributeError, OSError):
        raise protocol.WorkerFailure("insufficient_memory") from None
    return int(status.ullAvailPhys)


def _validate_cpu_platform_and_resources(temp_parent: Path) -> None:
    if os.name != "nt" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise protocol.WorkerFailure("unsupported_platform")
    temp_text = str(temp_parent)
    if (
        not temp_parent.is_absolute()
        or temp_text.startswith(("\\\\", "//"))
        or _has_reparse_in_path(temp_parent)
    ):
        raise protocol.WorkerFailure("insufficient_temp_disk")
    try:
        if shutil.disk_usage(temp_parent).free < MIN_TEMP_DISK_BYTES:
            raise protocol.WorkerFailure("insufficient_temp_disk")
    except protocol.WorkerFailure:
        raise
    except OSError:
        raise protocol.WorkerFailure("insufficient_temp_disk") from None
    if _available_physical_memory_bytes() < MIN_AVAILABLE_MEMORY_BYTES:
        raise protocol.WorkerFailure("insufficient_memory")


@contextlib.contextmanager
def _offline_runtime_environment(temp_root: Path):
    environment = {
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_DISABLE_PROGRESS_BARS": "1",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "TRANSFORMERS_VERBOSITY": "error",
        "TOKENIZERS_PARALLELISM": "false",
        "OMP_NUM_THREADS": "2",
        "MKL_NUM_THREADS": "2",
        "OPENBLAS_NUM_THREADS": "1",
        "HF_HOME": str(temp_root / "hf-home"),
        "HF_HUB_CACHE": str(temp_root / "hf-home" / "hub"),
        "TRANSFORMERS_CACHE": str(temp_root / "transformers-cache"),
        "TORCH_HOME": str(temp_root / "torch-home"),
        "TMP": str(temp_root),
        "TEMP": str(temp_root),
    }
    previous = {key: os.environ.get(key) for key in environment}
    previous_log_disable = logging.root.manager.disable
    os.environ.update(environment)
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(previous_log_disable)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _validate_runtime_versions() -> None:
    if sys.version_info[:3] != EXPECTED_PYTHON:
        raise protocol.WorkerFailure("runtime_version_mismatch")
    try:
        profile, _profile_digest = runtime_profile.load_profile()
        installed = runtime_profile.installed_distribution_versions()
        runtime_profile.validate_installed_distribution_closure(profile, installed)
    except runtime_profile.RuntimeProfileError:
        raise protocol.WorkerFailure("runtime_version_mismatch") from None


def _validate_generated_token_count(count: int) -> None:
    if type(count) is not int or not 0 <= count <= MAX_GENERATED_TOKENS:
        raise protocol.WorkerFailure("inference_failed")


def _normalize_eos_token_ids(eos_token_id: object) -> set[int]:
    if type(eos_token_id) is int and eos_token_id >= 0:
        return {eos_token_id}
    if (
        type(eos_token_id) is list
        and eos_token_id
        and all(type(token_id) is int and token_id >= 0 for token_id in eos_token_id)
    ):
        return set(eos_token_id)
    raise protocol.WorkerFailure("inference_failed")


def _validate_generation_termination(
    generated, input_token_count: int, eos_token_id: object
) -> None:
    eos_token_ids = _normalize_eos_token_ids(eos_token_id)
    try:
        shape = generated.shape
        if len(shape) != 2 or shape[0] != 1:
            raise protocol.WorkerFailure("inference_failed")
        sequence_length = int(shape[-1])
        generated_token_count = sequence_length - input_token_count
        _validate_generated_token_count(generated_token_count)
        if generated_token_count == 0:
            raise protocol.WorkerFailure("inference_failed")
        last_token_id = generated[0, sequence_length - 1]
        if hasattr(last_token_id, "item"):
            last_token_id = last_token_id.item()
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("inference_failed") from None
    if type(last_token_id) is not int or last_token_id not in eos_token_ids:
        raise protocol.WorkerFailure("inference_failed")


def _decode_generated_text(processor, generated, input_token_count: int) -> str:
    decoded = processor.batch_decode(
        generated[:, input_token_count:],
        skip_special_tokens=True,
        clean_up_tokenization_spaces=False,
    )
    if type(decoded) is not list or len(decoded) != 1 or type(decoded[0]) is not str:
        raise protocol.WorkerFailure("inference_failed")
    text = decoded[0]
    if len(text.encode("utf-8", errors="strict")) > protocol.MAX_TEXT_BYTES:
        raise protocol.WorkerFailure("inference_failed")
    return text


def _import_pillow_image():
    try:
        from PIL import Image
    except ImportError:
        raise protocol.WorkerFailure("runtime_version_mismatch") from None
    return Image


def _require_static_single_frame_png(image) -> None:
    is_animated = getattr(image, "is_animated", False)
    frame_count = getattr(image, "n_frames", 1)
    default_image = getattr(image, "info", {}).get("default_image", False)
    mime_getter = getattr(image, "get_format_mimetype", None)
    mime_type = mime_getter() if callable(mime_getter) else None
    if (
        is_animated is not False
        or type(frame_count) is not int
        or frame_count != 1
        or default_image is True
        or mime_type == "image/apng"
    ):
        raise protocol.WorkerFailure("raster_decode_failed")


def _decode_png_rgb(
    raster: dict[str, protocol.JsonValue],
    *,
    image_loader: Callable[[], object] | None = None,
):
    width = raster.get("width")
    height = raster.get("height")
    payload_hex = raster.get("raw_payload_hex")
    if (
        type(width) is not int
        or type(height) is not int
        or width <= 0
        or height <= 0
        or width * height > MAX_RASTER_PIXELS
        or type(payload_hex) is not str
        or len(payload_hex) % 2
        or len(payload_hex) // 2 > MAX_RASTER_BYTES
        or any(character not in "0123456789abcdefABCDEF" for character in payload_hex)
    ):
        raise protocol.WorkerFailure("raster_decode_failed")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        raise protocol.WorkerFailure("raster_decode_failed") from None
    if (
        len(payload) < 33
        or payload[24] != 8
        or payload[25] not in {2, 6}
        or payload[26] != 0
        or payload[27] != 0
        or payload[28] != 0
    ):
        raise protocol.WorkerFailure("raster_decode_failed")
    try:
        Image = (image_loader or _import_pillow_image)()
    except protocol.WorkerFailure:
        raise
    except ImportError:
        raise protocol.WorkerFailure("runtime_version_mismatch") from None
    try:
        with Image.open(io.BytesIO(payload)) as probe:
            if probe.format != "PNG" or probe.size != (width, height):
                raise protocol.WorkerFailure("raster_decode_failed")
            _require_static_single_frame_png(probe)
            probe.verify()
        with Image.open(io.BytesIO(payload)) as decoded:
            if decoded.format != "PNG" or decoded.size != (width, height):
                raise protocol.WorkerFailure("raster_decode_failed")
            _require_static_single_frame_png(decoded)
            decoded.load()
            color_type = payload[25]
            if color_type == 2 and decoded.mode == "RGB":
                return decoded.copy()
            if color_type == 6 and decoded.mode == "RGBA":
                alpha = decoded.getchannel("A")
                if alpha.getextrema() != (255, 255):
                    raise protocol.WorkerFailure("raster_decode_failed")
                return decoded.convert("RGB")
            raise protocol.WorkerFailure("raster_decode_failed")
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("raster_decode_failed") from None


def _senocr_e2e_shared_files() -> tuple[Path, Path] | None:
    if os.environ.get("LASSOINK_RUN_SENOCR_M4_E2E") != "1":
        return None
    expected_sha = os.environ.get("LASSOINK_EXPECTED_HEAD_SHA", "")
    expected_head_ref = os.environ.get("LASSOINK_EXPECTED_HEAD_REF", "")
    required = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows",
        "RUNNER_ARCH": "X64",
        "GITHUB_REPOSITORY": "Herzchens/LassoInk",
        "LASSOINK_EXPECTED_HEAD_REPOSITORY": "Herzchens/LassoInk",
        "LASSOINK_RUN_SENOCR_CPU_COMPAT": "1",
    }
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise protocol.WorkerFailure("runtime_version_mismatch")
    if any(os.environ.get(key) != value for key, value in required.items()):
        raise protocol.WorkerFailure("runtime_version_mismatch")
    if (
        os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
        or os.environ.get("GITHUB_BASE_REF") != "main"
        or expected_head_ref not in {"feat/benchmark-fidelity", "repair/ci-green-history"}
        or os.environ.get("GITHUB_HEAD_REF") != expected_head_ref
    ):
        raise protocol.WorkerFailure("runtime_version_mismatch")
    if (
        len(expected_sha) != 40
        or any(character not in "0123456789abcdef" for character in expected_sha)
        or os.environ.get("LASSOINK_CHECKED_OUT_HEAD_SHA") != expected_sha
    ):
        raise protocol.WorkerFailure("runtime_version_mismatch")
    try:
        runner_temp_input = Path(os.environ["RUNNER_TEMP"])
        shared_dir_input = Path(os.environ["LASSOINK_SENOCR_E2E_SHARED_DIR"])
        if (
            not runner_temp_input.is_absolute()
            or not shared_dir_input.is_absolute()
            or shared_dir_input.is_symlink()
        ):
            raise protocol.WorkerFailure("runtime_version_mismatch")
        runner_temp = runner_temp_input.resolve(strict=True)
        shared_dir = shared_dir_input.resolve(strict=True)
    except protocol.WorkerFailure:
        raise
    except (KeyError, OSError, RuntimeError):
        raise protocol.WorkerFailure("runtime_version_mismatch") from None
    if (
        shared_dir.parent != runner_temp
        or shared_dir.name != "lasso-senocr-worker-e2e"
        or not shared_dir.is_dir()
        or shared_dir.is_symlink()
    ):
        raise protocol.WorkerFailure("runtime_version_mismatch")
    rgba_path = shared_dir / "canonical-rgba.bin"
    sidecar_path = shared_dir / "processor-parity.json"
    try:
        invalid_test_files = (
            rgba_path.is_symlink()
            or not rgba_path.is_file()
            or rgba_path.stat().st_size > MAX_RASTER_PIXELS * 4
            or sidecar_path.exists()
            or sidecar_path.is_symlink()
        )
    except OSError:
        raise protocol.WorkerFailure("runtime_version_mismatch") from None
    if invalid_test_files:
        raise protocol.WorkerFailure("runtime_version_mismatch")
    return rgba_path, sidecar_path


def _processor_tensor_summary(inputs, torch) -> dict[str, dict[str, object]]:
    try:
        keys = sorted(inputs.keys())
        if not keys or len(keys) > 32 or "input_ids" not in keys or len(keys) < 2:
            raise protocol.WorkerFailure("inference_failed")
        total_bytes = 0
        summary: dict[str, dict[str, object]] = {}
        for key in keys:
            if type(key) is not str or not torch.is_tensor(inputs[key]):
                raise protocol.WorkerFailure("inference_failed")
            source_tensor = inputs[key]
            shape = [int(dimension) for dimension in source_tensor.shape]
            tensor_bytes = int(source_tensor.numel()) * int(source_tensor.element_size())
            total_bytes += tensor_bytes
            if tensor_bytes < 0 or total_bytes > MAX_E2E_PROCESSOR_TENSOR_BYTES:
                raise protocol.WorkerFailure("inference_failed")
            tensor = source_tensor.detach().to(device="cpu")
            if not tensor.is_contiguous():
                tensor = tensor.contiguous()
            raw_bytes = tensor.view(torch.uint8).numpy().tobytes()
            if len(raw_bytes) != tensor_bytes:
                raise protocol.WorkerFailure("inference_failed")
            summary[key] = {
                "dtype": str(tensor.dtype),
                "shape": shape,
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            }
        return summary
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("inference_failed") from None


def _verify_and_record_e2e_processor_parity(
    processor, decoded_image, decoded_inputs, torch
) -> None:
    paths = _senocr_e2e_shared_files()
    if paths is None:
        return
    rgba_path, sidecar_path = paths
    width, height = decoded_image.size
    if (
        type(width) is not int
        or type(height) is not int
        or width <= 0
        or height <= 0
    ):
        raise protocol.WorkerFailure("raster_decode_failed")
    pixel_count = width * height
    if pixel_count > MAX_RASTER_PIXELS:
        raise protocol.WorkerFailure("raster_decode_failed")
    expected_rgba_bytes = pixel_count * 4
    try:
        with rgba_path.open("rb") as pixel_stream:
            canonical_rgba = pixel_stream.read(expected_rgba_bytes + 1)
    except OSError:
        raise protocol.WorkerFailure("raster_decode_failed") from None
    if len(canonical_rgba) != expected_rgba_bytes:
        raise protocol.WorkerFailure("raster_decode_failed")
    canonical_rgb = bytearray(pixel_count * 3)
    for source_offset in range(0, expected_rgba_bytes, 4):
        if canonical_rgba[source_offset + 3] != 255:
            raise protocol.WorkerFailure("raster_decode_failed")
        target_offset = (source_offset // 4) * 3
        canonical_rgb[target_offset : target_offset + 3] = canonical_rgba[
            source_offset : source_offset + 3
        ]
    canonical_rgb_bytes = bytes(canonical_rgb)
    decoded_rgb_bytes = decoded_image.tobytes()
    if decoded_image.mode != "RGB" or decoded_rgb_bytes != canonical_rgb_bytes:
        raise protocol.WorkerFailure("raster_decode_failed")

    Image = _import_pillow_image()
    direct_image = Image.frombytes("RGB", (width, height), canonical_rgb_bytes)
    direct_messages = [
        {
            "role": "user",
            "content": [
                {"type": "image", "image": direct_image},
                {"type": "text", "text": "OCR:"},
            ],
        }
    ]
    try:
        direct_inputs = processor.apply_chat_template(
            direct_messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        ).to("cpu")
    except Exception:
        raise protocol.WorkerFailure("inference_failed") from None
    decoded_summary = _processor_tensor_summary(decoded_inputs, torch)
    direct_summary = _processor_tensor_summary(direct_inputs, torch)
    if decoded_summary != direct_summary:
        raise protocol.WorkerFailure("inference_failed")

    sidecar = {
        "schema": "senocr-processor-parity-v1",
        "width": width,
        "height": height,
        "canonical_rgba_sha256": hashlib.sha256(canonical_rgba).hexdigest(),
        "canonical_rgb_sha256": hashlib.sha256(canonical_rgb_bytes).hexdigest(),
        "decoded_png_rgb_sha256": hashlib.sha256(decoded_rgb_bytes).hexdigest(),
        "decoded_processor_inputs": decoded_summary,
        "direct_processor_inputs": direct_summary,
    }
    sidecar_bytes = json.dumps(
        sidecar, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(sidecar_bytes) > MAX_E2E_SIDECAR_BYTES:
        raise protocol.WorkerFailure("inference_failed")
    try:
        with sidecar_path.open("xb") as sidecar_stream:
            sidecar_stream.write(sidecar_bytes)
            sidecar_stream.flush()
    except OSError:
        raise protocol.WorkerFailure("inference_failed") from None


def _validate_loading_info(loading_info: object) -> None:
    expected = {"missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs"}
    if type(loading_info) is not dict or set(loading_info) != expected:
        raise protocol.WorkerFailure("model_load_failed")
    for key in ("missing_keys", "unexpected_keys", "mismatched_keys"):
        if type(loading_info[key]) is not set or loading_info[key]:
            raise protocol.WorkerFailure("model_load_failed")
    if type(loading_info["error_msgs"]) is not list or loading_info["error_msgs"]:
        raise protocol.WorkerFailure("model_load_failed")


def _load_local_model(asset_root: Path):
    try:
        import torch
        from transformers import AutoProcessor
        from transformers.models.paddleocr_vl.modeling_paddleocr_vl import (
            PaddleOCRVLForConditionalGeneration,
        )

        if torch.version.cuda is not None:
            raise protocol.WorkerFailure("runtime_version_mismatch")
        torch.set_num_threads(2)
        torch.set_num_interop_threads(1)
        processor = AutoProcessor.from_pretrained(
            asset_root,
            local_files_only=True,
            trust_remote_code=False,
        )
        model, loading_info = PaddleOCRVLForConditionalGeneration.from_pretrained(
            asset_root,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
            dtype=torch.float32,
            attn_implementation="eager",
            ignore_mismatched_sizes=False,
            output_loading_info=True,
        )
        _validate_loading_info(loading_info)
        if not model.__class__.__module__.startswith("transformers.models.paddleocr_vl."):
            raise protocol.WorkerFailure("model_load_failed")
        if not processor.__class__.__module__.startswith("transformers.models.paddleocr_vl."):
            raise protocol.WorkerFailure("model_load_failed")
        model.to("cpu")
        model.eval()
        parameters = list(model.parameters())
        if not parameters or any(
            parameter.device.type != "cpu" or parameter.dtype != torch.float32
            for parameter in parameters
        ):
            raise protocol.WorkerFailure("model_load_failed")
        return torch, processor, model
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("model_load_failed") from None


def _generate_raw_text(runtime, image) -> str:
    torch, processor, model = runtime
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "image", "image": image},
                {"type": "text", "text": "OCR:"},
            ],
        }
    ]
    started = time.monotonic()
    try:
        inputs = processor.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        ).to("cpu")
        _verify_and_record_e2e_processor_parity(
            processor, image, inputs, torch
        )
        input_token_count = int(inputs["input_ids"].shape[-1])
        with torch.inference_mode():
            generated = model.generate(
                **inputs,
                max_new_tokens=MAX_GENERATED_TOKENS,
                max_time=MAX_GENERATION_SECONDS,
                do_sample=False,
                num_beams=1,
                use_cache=False,
            )
        elapsed = time.monotonic() - started
        if elapsed > MAX_GENERATION_SECONDS or generated.ndim != 2 or generated.shape[0] != 1:
            raise protocol.WorkerFailure("inference_failed")
        generated_token_count = int(generated.shape[-1]) - input_token_count
        _validate_generated_token_count(generated_token_count)
        generation_config = getattr(model, "generation_config", None)
        _validate_generation_termination(
            generated,
            input_token_count,
            getattr(generation_config, "eos_token_id", None),
        )
        return _decode_generated_text(processor, generated, input_token_count)
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("inference_failed") from None


def _execute_senocr_pipeline(
    request: dict[str, protocol.JsonValue],
    *,
    asset_verifier: Callable[[Path], None],
    resource_guard: Callable[[], None],
    runtime_guard: Callable[[], None],
    image_decoder: Callable[[dict[str, protocol.JsonValue]], object],
    model_loader: Callable[[Path], object],
    generator: Callable[[object, object], str],
) -> str:
    request = protocol.validate_raster_recognition_request(request)
    model_root = validate_senocr_provider_configuration(request["provider_configuration"])
    if request["provider_configuration_fingerprint"] != protocol.provider_configuration_fingerprint(
        request["provider_configuration"]
    ):
        raise protocol.WorkerFailure("invalid_provider_configuration")
    resource_guard()
    runtime_guard()
    try:
        asset_verifier(model_root)
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("asset_read_failed") from None
    try:
        image = image_decoder(request["raster"])
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("raster_decode_failed") from None
    resource_guard()
    try:
        runtime = model_loader(model_root)
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("model_load_failed") from None
    try:
        raw_text = generator(runtime, image)
    except protocol.WorkerFailure:
        raise
    except Exception:
        raise protocol.WorkerFailure("inference_failed") from None
    if type(raw_text) is not str or len(raw_text.encode("utf-8", errors="strict")) > protocol.MAX_TEXT_BYTES:
        raise protocol.WorkerFailure("inference_failed")
    return raw_text


def _run_after_senocr_e2e_context_guard(
    request: dict[str, protocol.JsonValue],
    *,
    context_guard: Callable[[], object],
    request_processor: Callable[[dict[str, protocol.JsonValue]], str],
) -> str:
    context_guard()
    return request_processor(request)


def process_senocr_request(request: dict[str, protocol.JsonValue]) -> str:
    """Guard test-only context before resource, asset, decode, or model work."""
    return _run_after_senocr_e2e_context_guard(
        request,
        context_guard=_senocr_e2e_shared_files,
        request_processor=_process_senocr_request_after_context_guard,
    )


def _process_senocr_request_after_context_guard(
    request: dict[str, protocol.JsonValue],
) -> str:
    """Verify local artifacts, fully decode PNG, then lazily load/infer on CPU."""
    validate_senocr_provider_configuration(request["provider_configuration"])
    _validate_runtime_versions()
    temp_parent = Path(tempfile.gettempdir())
    _validate_cpu_platform_and_resources(temp_parent)
    try:
        with tempfile.TemporaryDirectory(
            prefix="lasso-senocr-local-", dir=temp_parent
        ) as temporary_directory:
            temp_root = Path(temporary_directory)
            with _offline_runtime_environment(temp_root):
                return _execute_senocr_pipeline(
                    request,
                    asset_verifier=verify_senocr_asset_directory,
                    resource_guard=lambda: _validate_cpu_platform_and_resources(temp_parent),
                    runtime_guard=_validate_runtime_versions,
                    image_decoder=_decode_png_rgb,
                    model_loader=lambda root: _load_local_model(root),
                    generator=_generate_raw_text,
                )
    except protocol.WorkerFailure:
        raise
    except OSError:
        raise protocol.WorkerFailure("insufficient_temp_disk") from None


def run_senocr_worker(input_stream: BinaryIO, output_stream: BinaryIO) -> None:
    """Serve one explicitly selected local SenOCR request over M4 stdio frames."""
    protocol.run_one_shot_raster_session(
        input_stream,
        output_stream,
        provider_identity=SENOCR_PROVIDER_IDENTITY,
        capabilities=SENOCR_CAPABILITIES,
        provider_provenance=SENOCR_PROVIDER_PROVENANCE,
        processor=process_senocr_request,
    )


class _SanitizedDiagnosticRedirect:
    """Replace incidental Python text/binary writes with one bounded marker."""

    encoding = "utf-8"
    errors = "replace"

    def __init__(self, target) -> None:
        self._target = target
        self._notified = False
        self._binary = _SanitizedBinaryDiagnosticRedirect(self)

    @property
    def buffer(self):
        return self._binary

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("text diagnostic stream accepts strings")
        if value:
            self._notify()
        return len(value)

    def flush(self) -> None:
        self._target.flush()

    def isatty(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def _notify(self) -> None:
        if not self._notified:
            self._notified = True
            self._target.write("worker diagnostic output suppressed\n")
            self._target.flush()


class _SanitizedBinaryDiagnosticRedirect:
    def __init__(self, parent: _SanitizedDiagnosticRedirect) -> None:
        self._parent = parent

    def write(self, value: bytes) -> int:
        if not isinstance(value, bytes):
            raise TypeError("binary diagnostic stream accepts bytes")
        if value:
            self._parent._notify()
        return len(value)

    def flush(self) -> None:
        self._parent.flush()


def main(
    *,
    input_stream: BinaryIO | None = None,
    frame_stream: BinaryIO | None = None,
    diagnostic_stream=None,
    worker: Callable[[BinaryIO, BinaryIO], None] | None = None,
) -> int:
    """Run one M4 session with protocol-only stdout and safe diagnostics."""
    input_stream = input_stream if input_stream is not None else sys.stdin.buffer
    frame_stream = frame_stream if frame_stream is not None else sys.stdout.buffer
    diagnostic_stream = diagnostic_stream if diagnostic_stream is not None else sys.stderr
    worker = worker if worker is not None else run_senocr_worker
    safe_redirect = _SanitizedDiagnosticRedirect(diagnostic_stream)

    with contextlib.redirect_stdout(safe_redirect), contextlib.redirect_stderr(
        safe_redirect
    ):
        try:
            worker(input_stream, frame_stream)
        except protocol.ProtocolError:
            diagnostic_stream.write("worker_protocol_error\n")
            diagnostic_stream.flush()
            return 1
        except KeyboardInterrupt:
            diagnostic_stream.write("worker_cancelled\n")
            diagnostic_stream.flush()
            return 130
        except Exception:
            diagnostic_stream.write("worker_internal_error\n")
            diagnostic_stream.flush()
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
