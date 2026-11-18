"""Bounded stdlib framing/config helpers for an optional local Raster worker.

This module does not launch a process, load a model, or construct a successful
recognition result. Handshake claims stay provisional until the full config is
checked. It never reads project metadata or selects an executable.
"""

from __future__ import annotations

import copy
import json
import math
import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Callable, Mapping, TypeAlias


PROTOCOL_VERSION = 1
MAX_HANDSHAKE_FRAME_BYTES = 64 * 1024
MAX_REQUEST_FRAME_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_FRAME_BYTES = 2 * 1024 * 1024
MAX_CONFIGURATION_BYTES = MAX_REQUEST_FRAME_BYTES // 4
MAX_CONFIGURATION_ENTRIES = 128
MAX_CONFIGURATION_ID_BYTES = 256
MAX_SETTING_KEY_BYTES = 128
MAX_SETTING_VALUE_BYTES = 2048
MAX_JSON_DEPTH = 128
MAX_PROVIDER_STROKES = 512
MAX_PROVIDER_SAMPLES = 4096
MAX_RAW_SAMPLE_BYTES = 8192
MAX_TOTAL_RAW_SAMPLE_BYTES = 1024 * 1024
MAX_RASTER_INPUT_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 4096

_FRAME_LIMITS = {
    MAX_HANDSHAKE_FRAME_BYTES,
    MAX_REQUEST_FRAME_BYTES,
    MAX_RESPONSE_FRAME_BYTES,
}
_FNV64_OFFSET_BASIS = 0xCBF29CE484222325
_FNV64_PRIME = 0x100000001B3

JsonValue: TypeAlias = (
    bool
    | int
    | float
    | str
    | list["JsonValue"]
    | dict[str, "JsonValue"]
    | type(None)
)


class ProtocolError(ValueError):
    """A bounded framing, JSON, envelope, or configuration error."""


@dataclass(frozen=True, slots=True)
class HandshakeClaims:
    """Provisional identity values claimed by the app's handshake frame."""

    provider_id: str
    configuration_id: str
    configuration_fingerprint: str


def _validate_frame_limit(maximum: int) -> None:
    if type(maximum) is not int or maximum not in _FRAME_LIMITS:
        raise ProtocolError("unsupported protocol frame limit")


def _read_exact(stream: BinaryIO, count: int, label: str) -> bytes:
    output = bytearray()
    while len(output) < count:
        try:
            chunk = stream.read(count - len(output))
        except InterruptedError:
            continue
        if not chunk:
            raise ProtocolError(f"truncated {label}")
        output.extend(chunk)
    return bytes(output)


def read_frame(stream: BinaryIO, maximum: int) -> bytes | None:
    """Read one M4 frame; return None only for EOF before any prefix byte."""
    _validate_frame_limit(maximum)
    while True:
        try:
            first = stream.read(1)
            break
        except InterruptedError:
            continue
    if not first:
        return None
    prefix = first + _read_exact(stream, 3, "frame prefix")
    length = int.from_bytes(prefix, "big")
    if length == 0:
        raise ProtocolError("zero-length protocol frame")
    if length > maximum:
        raise ProtocolError("protocol frame exceeds its phase limit")
    return _read_exact(stream, length, "frame payload")


def _reject_duplicate_keys(
    pairs: list[tuple[str, JsonValue]],
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ProtocolError("non-finite JSON number is not permitted")


def decode_json_payload(payload: bytes) -> dict[str, JsonValue]:
    """Decode strict UTF-8 JSON and require an object at the frame root."""
    if not isinstance(payload, bytes) or not payload:
        raise ProtocolError("JSON frame payload is empty or has the wrong type")
    if len(payload) > MAX_REQUEST_FRAME_BYTES:
        raise ProtocolError("JSON frame payload exceeds the largest phase limit")
    try:
        decoded = payload.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except ProtocolError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise ProtocolError("invalid UTF-8 JSON frame") from error
    if type(value) is not dict:
        raise ProtocolError("protocol frame must contain a JSON object")
    _validate_decoded_json(value)
    return value


def _validate_decoded_json(value: JsonValue, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError("JSON nesting exceeds the protocol parser limit")
    if isinstance(value, str):
        _utf8_length(value, "JSON string")
    elif type(value) is float and not math.isfinite(value):
        raise ProtocolError("non-finite JSON number is not permitted")
    elif type(value) is list:
        for item in value:
            _validate_decoded_json(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            _utf8_length(key, "JSON object key")
            _validate_decoded_json(item, depth + 1)


def read_json_frame(stream: BinaryIO, maximum: int) -> dict[str, JsonValue] | None:
    payload = read_frame(stream, maximum)
    return None if payload is None else decode_json_payload(payload)


def _append_bounded(output: bytearray, value: bytes, maximum: int) -> None:
    if len(output) + len(value) > maximum:
        raise ProtocolError("serialized JSON frame exceeds its phase limit")
    output.extend(value)


def _append_string(output: bytearray, value: str, maximum: int) -> None:
    _append_bounded(output, b'"', maximum)
    short_escapes = {
        '"': b'\\"',
        "\\": b"\\\\",
        "\b": b"\\b",
        "\f": b"\\f",
        "\n": b"\\n",
        "\r": b"\\r",
        "\t": b"\\t",
    }
    for character in value:
        escaped = short_escapes.get(character)
        if escaped is not None:
            _append_bounded(output, escaped, maximum)
        elif ord(character) < 0x20:
            _append_bounded(output, f"\\u{ord(character):04x}".encode("ascii"), maximum)
        else:
            try:
                encoded = character.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise ProtocolError("JSON string is not valid Unicode scalar text") from error
            _append_bounded(output, encoded, maximum)
    _append_bounded(output, b'"', maximum)


def _append_json_value(
    output: bytearray,
    value: JsonValue,
    maximum: int,
    depth: int,
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError("JSON nesting exceeds the protocol parser limit")
    if value is None:
        _append_bounded(output, b"null", maximum)
    elif value is True:
        _append_bounded(output, b"true", maximum)
    elif value is False:
        _append_bounded(output, b"false", maximum)
    elif type(value) is int:
        if value < -(1 << 63) or value > (1 << 64) - 1:
            raise ProtocolError("integer is outside the protocol number range")
        _append_bounded(output, str(value).encode("ascii"), maximum)
    elif type(value) is float:
        if not math.isfinite(value):
            raise ProtocolError("non-finite JSON number is not permitted")
        try:
            encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode("ascii")
        except (TypeError, ValueError, OverflowError) as error:
            raise ProtocolError("invalid JSON number") from error
        _append_bounded(output, encoded, maximum)
    elif isinstance(value, str):
        _append_string(output, value, maximum)
    elif type(value) is list:
        if len(value) > maximum:
            raise ProtocolError("JSON array exceeds the frame limit")
        _append_bounded(output, b"[", maximum)
        for index, item in enumerate(value):
            if index:
                _append_bounded(output, b",", maximum)
            _append_json_value(output, item, maximum, depth + 1)
        _append_bounded(output, b"]", maximum)
    elif type(value) is dict:
        if len(value) > maximum:
            raise ProtocolError("JSON object exceeds the frame limit")
        _append_bounded(output, b"{", maximum)
        for index, (key, item) in enumerate(value.items()):
            if type(key) is not str:
                raise ProtocolError("JSON object keys must be strings")
            if index:
                _append_bounded(output, b",", maximum)
            _append_string(output, key, maximum)
            _append_bounded(output, b":", maximum)
            _append_json_value(output, item, maximum, depth + 1)
        _append_bounded(output, b"}", maximum)
    else:
        raise ProtocolError("unsupported value in JSON frame")


def encode_json_payload(value: Mapping[str, JsonValue], maximum: int) -> bytes:
    """Encode a compact UTF-8 JSON object without exceeding its phase cap."""
    _validate_frame_limit(maximum)
    if not isinstance(value, Mapping) or not value:
        raise ProtocolError("protocol frame must be a nonempty JSON object")
    if len(value) > maximum:
        raise ProtocolError("JSON object exceeds the frame limit")
    output = bytearray()
    _append_json_value(output, dict(value), maximum, 0)
    if not output:
        raise ProtocolError("JSON frame payload is empty")
    return bytes(output)


def encode_json_frame(value: Mapping[str, JsonValue], maximum: int) -> bytes:
    payload = encode_json_payload(value, maximum)
    return len(payload).to_bytes(4, "big") + payload


def write_json_frame(stream: BinaryIO, value: Mapping[str, JsonValue], maximum: int) -> None:
    frame = encode_json_frame(value, maximum)
    view = memoryview(frame)
    while view:
        try:
            written = stream.write(view)
        except InterruptedError:
            continue
        if written is None or written <= 0:
            raise ProtocolError("protocol frame write made no progress")
        view = view[written:]
    while True:
        try:
            stream.flush()
            break
        except InterruptedError:
            continue


def _utf8_length(value: str, label: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise ProtocolError(f"{label} is not valid Unicode scalar text") from error


def validate_provider_configuration(configuration: object) -> dict[str, JsonValue]:
    """Validate and return the M4 ProviderConfigurationV1 wire object."""
    if type(configuration) is not dict or set(configuration) != {
        "configuration_id",
        "values",
    }:
        raise ProtocolError("provider configuration has an invalid shape")
    configuration_id = configuration["configuration_id"]
    values = configuration["values"]
    if type(configuration_id) is not str or not configuration_id:
        raise ProtocolError("provider configuration ID must be a nonempty string")
    if _utf8_length(configuration_id, "provider configuration ID") > MAX_CONFIGURATION_ID_BYTES:
        raise ProtocolError("provider configuration ID exceeds its byte cap")
    if type(values) is not dict or len(values) > MAX_CONFIGURATION_ENTRIES:
        raise ProtocolError("provider configuration values exceed their entry cap")
    total_bytes = _utf8_length(configuration_id, "provider configuration ID")
    for key, value in values.items():
        if type(key) is not str or not key:
            raise ProtocolError("provider setting keys must be nonempty strings")
        if type(value) is not str:
            raise ProtocolError("provider setting values must be strings")
        key_bytes = _utf8_length(key, "provider setting key")
        value_bytes = _utf8_length(value, "provider setting value")
        if key_bytes > MAX_SETTING_KEY_BYTES or value_bytes > MAX_SETTING_VALUE_BYTES:
            raise ProtocolError("provider setting exceeds its byte cap")
        total_bytes += key_bytes + value_bytes
        if total_bytes > MAX_CONFIGURATION_BYTES:
            raise ProtocolError("provider configuration exceeds its byte cap")
    canonical = {
        "configuration_id": configuration_id,
        "values": {key: values[key] for key in sorted(values)},
    }
    encode_json_payload(canonical, MAX_CONFIGURATION_BYTES)
    return canonical


def provider_configuration_json(configuration: object) -> bytes:
    canonical = validate_provider_configuration(configuration)
    return encode_json_payload(canonical, MAX_CONFIGURATION_BYTES)


def provider_configuration_fingerprint(configuration: object) -> str:
    payload = provider_configuration_json(configuration)
    fingerprint = _FNV64_OFFSET_BASIS
    for byte in payload:
        fingerprint = ((fingerprint ^ byte) * _FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return f"provider-config-v1-fnv64-{fingerprint:016x}"


def validate_handshake_request(
    frame: object,
) -> HandshakeClaims:
    """Validate and retain handshake identity claims until config is disclosed."""
    if type(frame) is not dict or frame.get("kind") != "handshake":
        raise ProtocolError("expected a handshake request")
    if (
        type(frame.get("protocol_version")) is not int
        or frame["protocol_version"] != PROTOCOL_VERSION
    ):
        raise ProtocolError("unsupported provider protocol version")
    provider_id = frame.get("provider_id")
    configuration_id = frame.get("configuration_id")
    fingerprint = frame.get("configuration_fingerprint")
    for value, label in (
        (provider_id, "provider ID"),
        (configuration_id, "configuration ID"),
    ):
        if type(value) is not str or not value:
            raise ProtocolError(f"{label} must be a nonempty string")
        if _utf8_length(value, label) > MAX_CONFIGURATION_ID_BYTES:
            raise ProtocolError(f"{label} exceeds its byte cap")
    if (
        type(fingerprint) is not str
        or not fingerprint.startswith("provider-config-v1-fnv64-")
        or len(fingerprint) != len("provider-config-v1-fnv64-") + 16
        or any(character not in "0123456789abcdef" for character in fingerprint[-16:])
    ):
        raise ProtocolError("handshake configuration fingerprint has invalid syntax")
    return HandshakeClaims(provider_id, configuration_id, fingerprint)


def validate_recognition_request(
    frame: object,
    *,
    handshake_claims: HandshakeClaims | None,
) -> dict[str, JsonValue]:
    """Verify full config against handshake claims before returning the request."""
    if not isinstance(handshake_claims, HandshakeClaims):
        raise ProtocolError("recognition request arrived before a valid handshake")
    if type(frame) is not dict or frame.get("kind") != "recognize":
        raise ProtocolError("expected a recognition request")
    if (
        type(frame.get("protocol_version")) is not int
        or frame["protocol_version"] != PROTOCOL_VERSION
    ):
        raise ProtocolError("unsupported provider protocol version")
    request = frame.get("request")
    if type(request) is not dict:
        raise ProtocolError("recognition request must be a JSON object")
    if (
        type(request.get("protocol_version")) is not int
        or request["protocol_version"] != PROTOCOL_VERSION
    ):
        raise ProtocolError("unsupported recognition request protocol version")
    request_configuration = validate_provider_configuration(
        request.get("provider_configuration")
    )
    configuration_id = request_configuration["configuration_id"]
    fingerprint = request.get("provider_configuration_fingerprint")
    expected_fingerprint = provider_configuration_fingerprint(request_configuration)
    if (
        configuration_id != handshake_claims.configuration_id
        or fingerprint != handshake_claims.configuration_fingerprint
        or fingerprint != expected_fingerprint
    ):
        raise ProtocolError("request configuration does not match handshake claims")
    return request


def dispatch_verified_recognition_request(
    frame: object,
    *,
    handshake_claims: HandshakeClaims | None,
    processor: Callable[[dict[str, JsonValue]], object],
) -> object:
    """Dispatch only a fully verified Raster request to a caller processor."""
    request = validate_recognition_request(
        frame, handshake_claims=handshake_claims
    )
    request = validate_raster_recognition_request(request)
    return processor(request)


def _require_object(value: object, fields: set[str], label: str) -> dict[str, JsonValue]:
    if type(value) is not dict or set(value) != fields:
        raise ProtocolError(f"{label} has an invalid shape")
    return value


def _ordered_record(
    value: object,
    fields: tuple[str, ...],
    label: str,
) -> dict[str, JsonValue]:
    record = _require_object(value, set(fields), label)
    return {field: record[field] for field in fields}


def input_view_fingerprint_payload(request: object) -> bytes:
    """Serialize the M4 request-view fingerprint in its Rust struct field order."""
    value = _require_object(
        request,
        {
            "protocol_version",
            "request_id",
            "input_view_id",
            "source_revision",
            "region_id",
            "line_id",
            "coordinate_space",
            "coordinate_units",
            "language_hints",
            "requested_input_modalities",
            "provider_configuration",
            "provider_configuration_fingerprint",
            "stroke_views",
            "samples",
            "raster",
        },
        "RecognitionRequestV1",
    )
    revision = _require_object(
        value["source_revision"],
        {"journal_id", "logical_revision", "last_sequence"},
        "source revision",
    )
    ordered_stroke_views = []
    for view in value["stroke_views"]:
        record = _ordered_record(view, ("stroke", "view_frame"), "stroke view")
        stroke = _ordered_record(
            record["stroke"],
            (
                "journal_id",
                "session_id",
                "source_api",
                "device_id",
                "pointer_id",
                "stroke_id",
            ),
            "StrokeRef",
        )
        frame = record["view_frame"]
        if frame is not None:
            frame = _ordered_record(
                frame,
                (
                    "screen_origin_x_px",
                    "screen_origin_y_px",
                    "dpi_scale_factor_bits",
                    "canvas_zoom_bits",
                    "canvas_pan_x_bits",
                    "canvas_pan_y_bits",
                    "toolbar_height_px",
                ),
                "stroke view frame",
            )
        ordered_stroke_views.append({"stroke": stroke, "view_frame": frame})

    position_fields = ("coordinate_space", "units", "x_raw", "y_raw")
    pressure_fields = (
        "representation",
        "units",
        "value_raw",
        "mask_raw",
        "minimum_raw",
        "maximum_raw",
    )
    timestamp_fields = ("clock_domain", "units", "count_raw", "frequency_hz")
    ordered_samples = []
    for sample in value["samples"]:
        record = _ordered_record(
            sample,
            (
                "journal_sequence",
                "source_sequence_raw",
                "stroke",
                "app_arrival_elapsed_ns_decimal",
                "config_id",
                "position",
                "effective_position",
                "pressure",
                "native_timestamp",
                "contact_range_state",
                "button_state_raw",
                "tilt_x_raw",
                "tilt_y_raw",
                "rotation_raw",
                "raw_payload_hex",
            ),
            "provider sample",
        )
        record["stroke"] = _ordered_record(
            record["stroke"],
            (
                "journal_id",
                "session_id",
                "source_api",
                "device_id",
                "pointer_id",
                "stroke_id",
            ),
            "sample StrokeRef",
        )
        for field in ("position", "effective_position"):
            if record[field] is not None:
                record[field] = _ordered_record(
                    record[field], position_fields, f"sample {field}"
                )
        if record["pressure"] is not None:
            record["pressure"] = _ordered_record(
                record["pressure"], pressure_fields, "sample pressure"
            )
        if record["native_timestamp"] is not None:
            record["native_timestamp"] = _ordered_record(
                record["native_timestamp"], timestamp_fields, "sample timestamp"
            )
        ordered_samples.append(record)

    raster = value["raster"]
    if raster is not None:
        raster = _ordered_record(
            raster,
            (
                "width",
                "height",
                "payload_contract",
                "coordinate_space",
                "units",
                "raw_payload_hex",
            ),
            "Raster input",
        )
    fingerprint = {
        "protocol_version": value["protocol_version"],
        "source_journal_id": revision["journal_id"],
        "logical_revision": revision["logical_revision"],
        "region_id": value["region_id"],
        "line_id": value["line_id"],
        "coordinate_space": value["coordinate_space"],
        "coordinate_units": value["coordinate_units"],
        "language_hints": value["language_hints"],
        "requested_input_modalities": value["requested_input_modalities"],
        "stroke_views": ordered_stroke_views,
        "samples": ordered_samples,
        "raster": raster,
    }
    return encode_json_payload(fingerprint, MAX_REQUEST_FRAME_BYTES)


def calculate_input_view_id(request: object) -> str:
    """Reproduce the M4 request-view FNV over its typed struct field order."""
    payload = input_view_fingerprint_payload(request)
    fingerprint_value = _FNV64_OFFSET_BASIS
    for byte in payload:
        fingerprint_value = (
            (fingerprint_value ^ byte) * _FNV64_PRIME
        ) & 0xFFFFFFFFFFFFFFFF
    return f"input-view-v1-{fingerprint_value:016x}"


def _require_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise ProtocolError(f"{label} must be a string")
    if _utf8_length(value, label) > MAX_CONFIGURATION_ID_BYTES:
        raise ProtocolError(f"{label} exceeds its byte cap")
    return value


def _require_uint(value: object, label: str, *, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ProtocolError(f"{label} is outside its unsigned integer range")
    return value


def _require_i64(value: object, label: str) -> int:
    if type(value) is not int or value < -(1 << 63) or value > (1 << 63) - 1:
        raise ProtocolError(f"{label} is outside its signed integer range")
    return value


def _validate_view_frame(frame: object) -> None:
    value = _require_object(
        frame,
        {
            "screen_origin_x_px",
            "screen_origin_y_px",
            "dpi_scale_factor_bits",
            "canvas_zoom_bits",
            "canvas_pan_x_bits",
            "canvas_pan_y_bits",
            "toolbar_height_px",
        },
        "stroke view frame",
    )
    _require_i64(value["screen_origin_x_px"], "screen origin x")
    _require_i64(value["screen_origin_y_px"], "screen origin y")
    dpi_bits = _require_uint(value["dpi_scale_factor_bits"], "DPI scale bits")
    zoom_bits = _require_uint(value["canvas_zoom_bits"], "canvas zoom bits")
    pan_x_bits = _require_uint(value["canvas_pan_x_bits"], "canvas pan x bits")
    pan_y_bits = _require_uint(value["canvas_pan_y_bits"], "canvas pan y bits")
    toolbar_height = _require_uint(
        value["toolbar_height_px"], "toolbar height", maximum=(1 << 32) - 1
    )
    dpi = struct.unpack(">d", dpi_bits.to_bytes(8, "big"))[0]
    zoom = struct.unpack(">d", zoom_bits.to_bytes(8, "big"))[0]
    pan_x = struct.unpack(">d", pan_x_bits.to_bytes(8, "big"))[0]
    pan_y = struct.unpack(">d", pan_y_bits.to_bytes(8, "big"))[0]
    if (
        not math.isfinite(dpi)
        or dpi <= 0.0
        or not math.isfinite(zoom)
        or not 0.2 <= zoom <= 8.0
        or not math.isfinite(pan_x)
        or not math.isfinite(pan_y)
        or toolbar_height > 4096
    ):
        raise ProtocolError("stroke view frame is invalid")


def _validate_position(position: object, label: str) -> None:
    value = _require_object(
        position, {"coordinate_space", "units", "x_raw", "y_raw"}, label
    )
    _require_text(value["coordinate_space"], f"{label} coordinate space")
    _require_text(value["units"], f"{label} units")
    _require_i64(value["x_raw"], f"{label} x")
    _require_i64(value["y_raw"], f"{label} y")


def _validate_pressure(pressure: object) -> None:
    value = _require_object(
        pressure,
        {"representation", "units", "value_raw", "mask_raw", "minimum_raw", "maximum_raw"},
        "sample pressure",
    )
    _require_text(value["representation"], "pressure representation")
    _require_text(value["units"], "pressure units")
    _require_uint(value["value_raw"], "pressure raw value")
    for field in ("mask_raw", "minimum_raw", "maximum_raw"):
        if value[field] is not None:
            _require_uint(value[field], f"pressure {field}")


def _validate_native_timestamp(timestamp: object) -> None:
    value = _require_object(
        timestamp,
        {"clock_domain", "units", "count_raw", "frequency_hz"},
        "native timestamp",
    )
    _require_text(value["clock_domain"], "native clock domain")
    _require_text(value["units"], "native clock units")
    _require_uint(value["count_raw"], "native timestamp count")
    if value["frequency_hz"] is not None:
        _require_uint(value["frequency_hz"], "native clock frequency")


def _stroke_key(stroke: dict[str, JsonValue]) -> tuple[object, ...]:
    return (
        stroke["journal_id"],
        stroke["session_id"],
        stroke["source_api"],
        stroke["device_id"],
        stroke["pointer_id"],
        stroke["stroke_id"],
    )


def _validate_stroke_ref(value: object, journal_id: str) -> tuple[object, ...]:
    stroke = _require_object(
        value,
        {"journal_id", "session_id", "source_api", "device_id", "pointer_id", "stroke_id"},
        "StrokeRef",
    )
    for field in ("journal_id", "session_id", "source_api", "stroke_id"):
        _require_text(stroke[field], f"StrokeRef {field}")
    if stroke["journal_id"] != journal_id:
        raise ProtocolError("sample StrokeRef does not match the source journal revision")
    device_id = stroke["device_id"]
    if device_id is not None:
        _require_text(device_id, "StrokeRef device ID")
    pointer_id = stroke["pointer_id"]
    if pointer_id is not None:
        _require_uint(pointer_id, "StrokeRef pointer ID")
    return _stroke_key(stroke)


def _validate_opaque_png(raster: object) -> None:
    value = _require_object(
        raster,
        {"width", "height", "payload_contract", "coordinate_space", "units", "raw_payload_hex"},
        "Raster input",
    )
    width = _require_uint(value["width"], "raster width", maximum=(1 << 32) - 1)
    height = _require_uint(value["height"], "raster height", maximum=(1 << 32) - 1)
    if width == 0 or height == 0 or width * height > MAX_TOTAL_RAW_SAMPLE_BYTES:
        raise ProtocolError("raster dimensions are empty or exceed their pixel cap")
    if value["payload_contract"] != "opaque_bytes":
        raise ProtocolError("unsupported raster payload contract")
    _require_text(value["coordinate_space"], "raster coordinate space")
    _require_text(value["units"], "raster units")
    payload_hex = value["raw_payload_hex"]
    if (
        type(payload_hex) is not str
        or not payload_hex
        or len(payload_hex) % 2
        or len(payload_hex) // 2 > MAX_RASTER_INPUT_BYTES
        or any(character not in "0123456789abcdefABCDEF" for character in payload_hex)
    ):
        raise ProtocolError("opaque raster payload is empty, malformed, or oversized")
    payload = bytes.fromhex(payload_hex)
    if len(payload) < 33 or payload[:8] != b"\x89PNG\r\n\x1a\n":
        raise ProtocolError("raster payload is not a bounded PNG with an IHDR")
    if int.from_bytes(payload[8:12], "big") != 13 or payload[12:16] != b"IHDR":
        raise ProtocolError("PNG does not start with a standard IHDR chunk")
    png_width = int.from_bytes(payload[16:20], "big")
    png_height = int.from_bytes(payload[20:24], "big")
    expected_crc = zlib.crc32(payload[12:29]) & 0xFFFFFFFF
    if int.from_bytes(payload[29:33], "big") != expected_crc:
        raise ProtocolError("PNG IHDR checksum is invalid")
    if png_width != width or png_height != height:
        raise ProtocolError("PNG IHDR dimensions do not match the request")


def validate_raster_recognition_request(request: object) -> dict[str, JsonValue]:
    """Validate M4 request identity/provenance and its Raster-only PNG input."""
    fields = {
        "protocol_version",
        "request_id",
        "input_view_id",
        "source_revision",
        "region_id",
        "line_id",
        "coordinate_space",
        "coordinate_units",
        "language_hints",
        "requested_input_modalities",
        "provider_configuration",
        "provider_configuration_fingerprint",
        "stroke_views",
        "samples",
        "raster",
    }
    value = _require_object(request, fields, "RecognitionRequestV1")
    if type(value["protocol_version"]) is not int or value["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported recognition request protocol version")
    for field in ("request_id", "region_id", "line_id", "coordinate_space", "coordinate_units"):
        _require_text(value[field], f"request {field}")
    input_view_id = _require_text(value["input_view_id"], "input-view ID")
    if (
        not input_view_id.startswith("input-view-v1-")
        or len(input_view_id) != len("input-view-v1-") + 16
        or any(character not in "0123456789abcdef" for character in input_view_id[-16:])
    ):
        raise ProtocolError("input-view ID has invalid syntax")

    revision = _require_object(
        value["source_revision"],
        {"journal_id", "logical_revision", "last_sequence"},
        "source revision",
    )
    journal_id = _require_text(revision["journal_id"], "source journal ID")
    _require_uint(revision["logical_revision"], "logical revision")
    last_sequence = _require_uint(revision["last_sequence"], "source last sequence")

    language_hints = value["language_hints"]
    if type(language_hints) is not list or len(language_hints) > 16:
        raise ProtocolError("language hints exceed their protocol limit")
    for hint in language_hints:
        if not _require_text(hint, "language hint") or _utf8_length(hint, "language hint") > 32:
            raise ProtocolError("language hint is empty or oversized")

    if value["requested_input_modalities"] != ["raster"]:
        raise ProtocolError("this frontend accepts Raster-only requests without fallback")
    if value["raster"] is None:
        raise ProtocolError("Raster input is required")
    _validate_opaque_png(value["raster"])

    stroke_views = value["stroke_views"]
    samples = value["samples"]
    if type(stroke_views) is not list or not 1 <= len(stroke_views) <= MAX_PROVIDER_STROKES:
        raise ProtocolError("stroke-view count is empty or exceeds its cap")
    if type(samples) is not list or not 1 <= len(samples) <= MAX_PROVIDER_SAMPLES:
        raise ProtocolError("sample count is empty or exceeds its cap")
    view_keys: list[tuple[object, ...]] = []
    for view in stroke_views:
        record = _require_object(view, {"stroke", "view_frame"}, "stroke view")
        key = _validate_stroke_ref(record["stroke"], journal_id)
        if key in view_keys:
            raise ProtocolError("duplicate StrokeRef in stroke views")
        view_keys.append(key)
        if record["view_frame"] is not None:
            _validate_view_frame(record["view_frame"])

    previous_sequence = 0
    total_raw_bytes = 0
    first_occurrence: list[tuple[object, ...]] = []
    seen: set[tuple[object, ...]] = set()
    sample_fields = {
        "journal_sequence",
        "source_sequence_raw",
        "stroke",
        "app_arrival_elapsed_ns_decimal",
        "config_id",
        "position",
        "effective_position",
        "pressure",
        "native_timestamp",
        "contact_range_state",
        "button_state_raw",
        "tilt_x_raw",
        "tilt_y_raw",
        "rotation_raw",
        "raw_payload_hex",
    }
    for sample in samples:
        record = _require_object(sample, sample_fields, "provider sample")
        sequence = _require_uint(record["journal_sequence"], "journal sequence")
        if sequence <= previous_sequence or sequence > last_sequence:
            raise ProtocolError("sample sequence disagrees with source revision")
        previous_sequence = sequence
        _require_uint(record["source_sequence_raw"], "source sequence")
        key = _validate_stroke_ref(record["stroke"], journal_id)
        if key not in view_keys:
            raise ProtocolError("sample StrokeRef is missing from the stroke views")
        if key not in seen:
            seen.add(key)
            first_occurrence.append(key)
        arrival = record["app_arrival_elapsed_ns_decimal"]
        if (
            type(arrival) is not str
            or not 1 <= len(arrival) <= 39
            or not arrival.isascii()
            or not arrival.isdigit()
            or int(arrival) > (1 << 128) - 1
        ):
            raise ProtocolError("sample app-arrival value is not bounded unsigned decimal")
        if record["config_id"] is not None:
            _require_text(record["config_id"], "sample config ID", allow_empty=True)
        if record["position"] is not None:
            _validate_position(record["position"], "raw position")
        if record["effective_position"] is not None:
            _validate_position(record["effective_position"], "effective position")
        if record["pressure"] is not None:
            _validate_pressure(record["pressure"])
        if record["native_timestamp"] is not None:
            _validate_native_timestamp(record["native_timestamp"])
        if record["contact_range_state"] is not None:
            if type(record["contact_range_state"]) is not str or _utf8_length(
                record["contact_range_state"], "sample contact/range state"
            ) > MAX_TEXT_BYTES:
                raise ProtocolError("sample contact/range state is invalid")
        if record["button_state_raw"] is not None:
            _require_uint(record["button_state_raw"], "sample button state")
        for field in ("tilt_x_raw", "tilt_y_raw"):
            if record[field] is not None:
                number = record[field]
                if type(number) is not int or not -(1 << 31) <= number <= (1 << 31) - 1:
                    raise ProtocolError(f"sample {field} is outside its signed range")
        if record["rotation_raw"] is not None:
            _require_uint(record["rotation_raw"], "sample rotation")
        payload_hex = record["raw_payload_hex"]
        if (
            type(payload_hex) is not str
            or len(payload_hex) % 2
            or len(payload_hex) // 2 > MAX_RAW_SAMPLE_BYTES
            or any(character not in "0123456789abcdefABCDEF" for character in payload_hex)
        ):
            raise ProtocolError("sample raw payload is not bounded hexadecimal")
        total_raw_bytes += len(payload_hex) // 2
        if total_raw_bytes > MAX_TOTAL_RAW_SAMPLE_BYTES:
            raise ProtocolError("total raw sample payload exceeds its cap")
    if first_occurrence != view_keys:
        raise ProtocolError("stroke views do not follow canonical sample order")
    if value["input_view_id"] != calculate_input_view_id(value):
        raise ProtocolError("input-view ID does not match the request payload")
    return value


def _validate_provider_advertisement(
    provider: object,
    capabilities: object,
    claimed_provider_id: str,
) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    identity = _require_object(
        provider,
        {"provider_id", "provider_version", "model_version", "resource_version"},
        "provider identity",
    )
    provider_id = _require_text(identity["provider_id"], "provider ID")
    _require_text(identity["provider_version"], "provider version")
    for field in ("model_version", "resource_version"):
        if identity[field] is not None:
            _require_text(identity[field], field, allow_empty=True)
    if provider_id != claimed_provider_id:
        raise ProtocolError("handshake provider ID does not match static provider identity")

    advertised = _require_object(
        capabilities,
        {"inputs", "outputs", "languages"},
        "provider capabilities",
    )
    inputs = advertised["inputs"]
    outputs = advertised["outputs"]
    languages = advertised["languages"]
    if inputs != ["raster"] or outputs != ["text"]:
        raise ProtocolError("this frontend may advertise only Raster input and text output")
    if type(languages) is not list or len(languages) > 128:
        raise ProtocolError("provider language capability list exceeds its cap")
    for language in languages:
        if not _require_text(language, "provider language") or _utf8_length(
            language, "provider language"
        ) > 32:
            raise ProtocolError("provider language capability is invalid")
    return identity, advertised


def build_text_response_frame(
    request: dict[str, JsonValue],
    provider: dict[str, JsonValue],
    provider_provenance: str,
    raw_text: str,
) -> dict[str, JsonValue]:
    """Build an identity-preserving Text response from caller-supplied raw text."""
    request = validate_raster_recognition_request(request)
    configuration = validate_provider_configuration(request["provider_configuration"])
    if request["provider_configuration_fingerprint"] != provider_configuration_fingerprint(
        configuration
    ):
        raise ProtocolError("response request configuration fingerprint is invalid")
    if (
        type(provider_provenance) is not str
        or not provider_provenance
        or _utf8_length(provider_provenance, "provider provenance") > MAX_TEXT_BYTES
    ):
        raise ProtocolError("provider provenance exceeds its byte cap")
    if type(raw_text) is not str or _utf8_length(raw_text, "provider text") > MAX_TEXT_BYTES:
        raise ProtocolError("provider text is invalid or oversized")
    return {
        "kind": "recognition",
        "protocol_version": PROTOCOL_VERSION,
        "result": {
            "request_id": request["request_id"],
            "input_view_id": request["input_view_id"],
            "source_revision": request["source_revision"],
            "region_id": request["region_id"],
            "line_id": request["line_id"],
            "provider_configuration_id": configuration["configuration_id"],
            "provider_configuration_fingerprint": request[
                "provider_configuration_fingerprint"
            ],
            "provider": provider,
            "provider_provenance": provider_provenance,
            "consumed_input_modalities": ["raster"],
            "candidates": [
                {
                    "recognized_text": raw_text,
                    "native_score_raw": None,
                    "stroke_ranges": [],
                    "raw_candidate": {},
                }
            ],
        },
    }


def run_one_shot_raster_session(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    provider_identity: object,
    capabilities: object,
    provider_provenance: str,
    processor: Callable[[dict[str, JsonValue]], str],
) -> None:
    """Run exactly one M4 handshake/request exchange without a default handler.

    Protocol errors propagate to the caller; no synthetic failure/success frame
    is emitted. The caller owns the process exit policy and any real processor.
    """
    handshake = read_json_frame(input_stream, MAX_HANDSHAKE_FRAME_BYTES)
    if handshake is None:
        raise ProtocolError("input ended before provider handshake")
    claims = validate_handshake_request(handshake)
    provider, advertised = _validate_provider_advertisement(
        provider_identity, capabilities, claims.provider_id
    )
    handshake_response = {
        "kind": "handshake",
        "protocol_version": PROTOCOL_VERSION,
        "provider": provider,
        "configuration_id": claims.configuration_id,
        "configuration_fingerprint": claims.configuration_fingerprint,
        "capabilities": advertised,
    }
    write_json_frame(output_stream, handshake_response, MAX_HANDSHAKE_FRAME_BYTES)

    recognition = read_json_frame(input_stream, MAX_REQUEST_FRAME_BYTES)
    if recognition is None:
        raise ProtocolError("input ended before recognition request")
    request = validate_recognition_request(recognition, handshake_claims=claims)
    request = validate_raster_recognition_request(request)
    if any(hint not in advertised["languages"] for hint in request["language_hints"]):
        raise ProtocolError("provider does not advertise every requested language")
    if read_frame(input_stream, MAX_REQUEST_FRAME_BYTES) is not None:
        raise ProtocolError("one-shot worker received an extra request frame")

    # The processor receives a bounded detached copy; it cannot rewrite the
    # request provenance that is echoed into the response.
    raw_text = processor(copy.deepcopy(request))
    response = build_text_response_frame(
        request,
        provider,
        provider_provenance,
        raw_text,
    )
    write_json_frame(output_stream, response, MAX_RESPONSE_FRAME_BYTES)
