"""Bounded stdlib framing/config helpers for an optional local Raster worker.

This module does not launch a process, load a model, or construct a successful
recognition result. Handshake claims stay provisional until the full config is
checked. It never reads project metadata or selects an executable.
"""

from __future__ import annotations

import json
import math
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
    """Invoke a caller-supplied processor only after exact config verification."""
    request = validate_recognition_request(
        frame, handshake_claims=handshake_claims
    )
    return processor(request)
