"""Pure tests for the optional stdlib Raster worker protocol frontend."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

from tools import raster_reference_protocol as protocol
from tools import senocr_fp32_worker as senocr
from tools import senocr_runtime_profile as runtime_profile


def require_senocr_hosted_e2e_guard(test_case: unittest.TestCase) -> None:
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
        "LASSOINK_RUN_SENOCR_M4_E2E": "1",
    }
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        test_case.fail("SenOCR integration tests require hosted Windows x64")
    for key, value in required.items():
        if os.environ.get(key) != value:
            test_case.fail(f"SenOCR integration test guard failed: {key}")
    if (
        os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
        or os.environ.get("GITHUB_BASE_REF") != "main"
        or expected_head_ref not in {"feat/benchmark-fidelity", "repair/ci-green-history"}
        or os.environ.get("GITHUB_HEAD_REF") != expected_head_ref
    ):
        test_case.fail("SenOCR pull request source guard failed")
    if (
        len(expected_sha) != 40
        or any(character not in "0123456789abcdef" for character in expected_sha)
        or os.environ.get("LASSOINK_CHECKED_OUT_HEAD_SHA") != expected_sha
    ):
        test_case.fail("SenOCR integration test exact-head guard failed")


def fixture_configuration() -> dict[str, object]:
    # Mirrors the operator-approved fixture in src/provider_protocol.rs:3470.
    return {
        "configuration_id": "operator-approved-config",
        "values": {"language-mode": "recognize"},
    }


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        len(data).to_bytes(4, "big")
        + kind
        + data
        + (zlib.crc32(kind + data) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def fixture_png(width: int = 1, height: int = 1) -> bytes:
    header = (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes((8, 6, 0, 0, 0))
    )
    scanlines = b"".join(b"\0" + b"\xff\xff\xff\xff" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(scanlines))
        + png_chunk(b"IEND", b"")
    )


def fixture_raster_request() -> dict[str, object]:
    configuration = fixture_configuration()
    stroke = {
        "journal_id": "journal-1",
        "session_id": "session-1",
        "source_api": "wmpointer",
        "device_id": None,
        "pointer_id": 7,
        "stroke_id": "stroke-1",
    }
    raster = fixture_png()
    request = {
        "protocol_version": 1,
        "request_id": "request-1",
        "input_view_id": "input-view-v1-0000000000000001",
        "source_revision": {
            "journal_id": "journal-1",
            "logical_revision": 0,
            "last_sequence": 1,
        },
        "region_id": "region-1",
        "line_id": "line-1",
        "coordinate_space": "document",
        "coordinate_units": "pixel",
        "language_hints": ["vi-VN"],
        "requested_input_modalities": ["raster"],
        "provider_configuration": configuration,
        "provider_configuration_fingerprint": protocol.provider_configuration_fingerprint(
            configuration
        ),
        "stroke_views": [{"stroke": stroke, "view_frame": None}],
        "samples": [
            {
                "journal_sequence": 1,
                "source_sequence_raw": 1,
                "stroke": stroke,
                "app_arrival_elapsed_ns_decimal": "10",
                "config_id": None,
                "position": None,
                "effective_position": None,
                "pressure": None,
                "native_timestamp": None,
                "contact_range_state": None,
                "button_state_raw": None,
                "tilt_x_raw": None,
                "tilt_y_raw": None,
                "rotation_raw": None,
                "raw_payload_hex": "",
            }
        ],
        "raster": {
            "width": 1,
            "height": 1,
            "payload_contract": "opaque_bytes",
            "coordinate_space": "document",
            "units": "pixel",
            "raw_payload_hex": raster.hex(),
        },
    }
    request["input_view_id"] = protocol.calculate_input_view_id(request)
    return request


def fixture_provider_identity() -> dict[str, object]:
    return {
        "provider_id": "local-reference",
        "provider_version": "stdlib-frontend-test-v1",
        "model_version": None,
        "resource_version": None,
    }


def fixture_capabilities() -> dict[str, object]:
    return {"inputs": ["raster"], "outputs": ["text"], "languages": ["vi-VN"]}


def run_session_input(
    request: dict[str, object],
    *,
    extra_request: dict[str, object] | None = None,
    handshake: dict[str, object] | None = None,
) -> io.BytesIO:
    configuration = fixture_configuration()
    handshake_frame = handshake or {
        "kind": "handshake",
        "protocol_version": 1,
        "provider_id": "local-reference",
        "configuration_id": configuration["configuration_id"],
        "configuration_fingerprint": protocol.provider_configuration_fingerprint(
            configuration
        ),
    }
    payload = (
        protocol.encode_json_frame(handshake_frame, protocol.MAX_HANDSHAKE_FRAME_BYTES)
        + protocol.encode_json_frame(
            {"kind": "recognize", "protocol_version": 1, "request": request},
            protocol.MAX_REQUEST_FRAME_BYTES,
        )
    )
    if extra_request is not None:
        payload += protocol.encode_json_frame(
            extra_request, protocol.MAX_REQUEST_FRAME_BYTES
        )
    return io.BytesIO(payload)


class FrameTests(unittest.TestCase):
    def test_compact_frame_round_trip_uses_big_endian_payload_length(self) -> None:
        value = {"kind": "handshake", "protocol_version": 1}
        payload = b'{"kind":"handshake","protocol_version":1}'
        frame = protocol.encode_json_frame(value, protocol.MAX_HANDSHAKE_FRAME_BYTES)
        self.assertEqual(frame, len(payload).to_bytes(4, "big") + payload)
        self.assertEqual(
            protocol.read_json_frame(
                io.BytesIO(frame), protocol.MAX_HANDSHAKE_FRAME_BYTES
            ),
            value,
        )
        self.assertIsNone(
            protocol.read_json_frame(io.BytesIO(b""), protocol.MAX_HANDSHAKE_FRAME_BYTES)
        )

    def test_phase_limits_zero_length_and_truncation_are_rejected(self) -> None:
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_frame(io.BytesIO(b"\0\0\0\0"), protocol.MAX_RESPONSE_FRAME_BYTES)
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_frame(
                io.BytesIO((protocol.MAX_HANDSHAKE_FRAME_BYTES + 1).to_bytes(4, "big")),
                protocol.MAX_HANDSHAKE_FRAME_BYTES,
            )
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_frame(io.BytesIO(b"\0"), protocol.MAX_REQUEST_FRAME_BYTES)
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_frame(io.BytesIO(b"\0\0\0\3{}"), protocol.MAX_REQUEST_FRAME_BYTES)
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_json_payload(
                {"message": "x" * protocol.MAX_HANDSHAKE_FRAME_BYTES},
                protocol.MAX_HANDSHAKE_FRAME_BYTES,
            )

    def test_payload_at_the_phase_limit_is_accepted(self) -> None:
        maximum = protocol.MAX_HANDSHAKE_FRAME_BYTES
        frame = protocol.encode_json_frame(
            {"x": "a" * (maximum - 8)}, maximum
        )
        self.assertEqual(int.from_bytes(frame[:4], "big"), maximum)
        self.assertEqual(len(frame) - 4, maximum)
        self.assertIsNotNone(protocol.read_frame(io.BytesIO(frame), maximum))

    def test_invalid_utf8_duplicate_keys_nonfinite_and_trailing_json_fail(self) -> None:
        for payload in (
            b"\xff",
            b'{"kind":"one","kind":"two"}',
            b'{"nested":{"x":1,"x":2}}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{} {}',
            b'[]',
        ):
            with self.subTest(payload=payload), self.assertRaises(protocol.ProtocolError):
                protocol.decode_json_payload(payload)

    def test_json_output_rejects_nonfinite_values_and_bad_roots(self) -> None:
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_json_payload({"value": float("nan")}, protocol.MAX_RESPONSE_FRAME_BYTES)
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_json_payload({}, protocol.MAX_RESPONSE_FRAME_BYTES)
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_json_payload(["not", "an", "object"], protocol.MAX_RESPONSE_FRAME_BYTES)  # type: ignore[arg-type]

    def test_json_uses_compact_utf8_and_rejects_overflowed_or_invalid_scalars(self) -> None:
        self.assertEqual(
            protocol.encode_json_payload(
                {"text": "café\n"}, protocol.MAX_RESPONSE_FRAME_BYTES
            ),
            b'{"text":"caf\xc3\xa9\\n"}',
        )
        for payload in (b'{"value":1e999}', b'{"value":"\\ud800"}'):
            with self.subTest(payload=payload), self.assertRaises(protocol.ProtocolError):
                protocol.decode_json_payload(payload)


class ConfigurationTests(unittest.TestCase):
    def test_fixture_compact_json_and_sorted_map_are_source_derived(self) -> None:
        config = fixture_configuration()
        config["values"] = {
            "z-mode": "last",
            "language-mode": "recognize",
            "a-mode": "first",
        }
        self.assertEqual(
            protocol.provider_configuration_json(config),
            b'{"configuration_id":"operator-approved-config","values":{"a-mode":"first","language-mode":"recognize","z-mode":"last"}}',
        )

    def test_rust_fixture_configuration_has_shared_json_and_fnv_vector(self) -> None:
        config = fixture_configuration()
        first = protocol.provider_configuration_fingerprint(config)
        self.assertEqual(
            protocol.provider_configuration_json(config),
            b'{"configuration_id":"operator-approved-config","values":{"language-mode":"recognize"}}',
        )
        self.assertEqual(
            first,
            "provider-config-v1-fnv64-5d449396c33394f8",
        )
        reordered = {
            "configuration_id": "operator-approved-config",
            "values": {
                "z-mode": "last",
                "language-mode": "recognize",
                "a-mode": "first",
            },
        }
        canonicalized = {
            "configuration_id": "operator-approved-config",
            "values": {
                "a-mode": "first",
                "language-mode": "recognize",
                "z-mode": "last",
            },
        }
        self.assertEqual(
            protocol.provider_configuration_fingerprint(reordered),
            protocol.provider_configuration_fingerprint(canonicalized),
        )
        changed = fixture_configuration()
        changed["values"] = {"language-mode": "dictation"}
        self.assertNotEqual(first, protocol.provider_configuration_fingerprint(changed))

    def test_unicode_windows_path_configuration_matches_shared_rust_json_bytes(self) -> None:
        fixture_path = (
            Path(__file__).parent
            / "fixtures"
            / "provider_configuration_unicode_path_v1.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(
            protocol.provider_configuration_json(fixture["configuration"]),
            fixture["canonical_json_utf8"].encode("utf-8"),
        )

    def test_input_view_payload_and_id_match_existing_rust_request_fixture(self) -> None:
        fixture_path = Path(__file__).parent / "fixtures" / "provider_input_view_v1.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        request = fixture["request"]
        self.assertEqual(
            protocol.input_view_fingerprint_payload(request).hex(),
            fixture["fingerprint_payload_hex"],
        )
        self.assertEqual(
            protocol.calculate_input_view_id(request),
            fixture["input_view_id"],
        )

    def test_raster_input_view_payload_and_id_match_rust_request_fixture(self) -> None:
        fixture_path = (
            Path(__file__).parent / "fixtures" / "provider_raster_input_view_v1.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        request = fixture["request"]
        self.assertEqual(request["requested_input_modalities"], ["raster"])
        self.assertEqual(
            protocol.input_view_fingerprint_payload(request).hex(),
            fixture["fingerprint_payload_hex"],
        )
        self.assertEqual(
            protocol.calculate_input_view_id(request),
            fixture["input_view_id"],
        )

    def test_configuration_limits_and_types_match_m4(self) -> None:
        config = fixture_configuration()
        config["values"] = {}
        self.assertEqual(protocol.validate_provider_configuration(config)["values"], {})

        invalid = [
            {},
            {"configuration_id": "", "values": {}},
            {"configuration_id": "id", "values": {}, "extra": True},
            {"configuration_id": "id", "values": []},
            {"configuration_id": "id", "values": {"": "value"}},
            {"configuration_id": "id", "values": {"key": 1}},
            {"configuration_id": "é" * 129, "values": {}},
            {"configuration_id": "id", "values": {"k" * 129: "v"}},
            {"configuration_id": "id", "values": {"k": "v" * 2049}},
            {
                "configuration_id": "id",
                "values": {f"key-{index}": "v" for index in range(129)},
            },
        ]
        for value in invalid:
            with self.subTest(configuration=value), self.assertRaises(protocol.ProtocolError):
                protocol.validate_provider_configuration(value)

        boundary = {
            "configuration_id": "é" * 128,
            "values": {"k" * 128: "v" * 2048},
        }
        self.assertEqual(
            protocol.validate_provider_configuration(boundary)["configuration_id"],
            "é" * 128,
        )
        maximum_entries = {
            "configuration_id": "id",
            "values": {f"key-{index}": "v" for index in range(128)},
        }
        self.assertEqual(
            len(protocol.validate_provider_configuration(maximum_entries)["values"]),
            protocol.MAX_CONFIGURATION_ENTRIES,
        )

    def test_recognition_config_is_verified_before_processor_dispatch(self) -> None:
        request = fixture_raster_request()
        configuration = request["provider_configuration"]
        fingerprint = request["provider_configuration_fingerprint"]
        handshake = {
            "kind": "handshake",
            "protocol_version": 1,
            "provider_id": "local-reference",
            "configuration_id": "operator-approved-config",
            "configuration_fingerprint": fingerprint,
        }
        claims = protocol.validate_handshake_request(handshake)
        self.assertEqual(claims.provider_id, "local-reference")
        self.assertEqual(claims.configuration_id, "operator-approved-config")
        self.assertEqual(claims.configuration_fingerprint, fingerprint)
        recognize = {
            "kind": "recognize",
            "protocol_version": 1,
            "request": request,
        }
        processed: list[dict[str, object]] = []
        outcome = protocol.dispatch_verified_recognition_request(
            recognize,
            handshake_claims=claims,
            processor=lambda checked: processed.append(checked) or "processor-called",
        )
        self.assertEqual(outcome, "processor-called")
        self.assertEqual(processed, [request])

        processed.clear()
        with self.assertRaises(protocol.ProtocolError):
            protocol.dispatch_verified_recognition_request(
                recognize,
                handshake_claims=None,
                processor=lambda checked: processed.append(checked),
            )
        self.assertEqual(processed, [])

        malformed_requests = []
        malformed_identity = copy.deepcopy(request)
        malformed_identity["request_id"] = ""
        malformed_requests.append(malformed_identity)
        wrong_mode = copy.deepcopy(request)
        wrong_mode["requested_input_modalities"] = ["online_strokes", "raster"]
        malformed_requests.append(wrong_mode)
        wrong_png_dimensions = copy.deepcopy(request)
        wrong_png_dimensions["raster"]["width"] = 2
        malformed_requests.append(wrong_png_dimensions)
        for malformed in malformed_requests:
            malformed_frame = {
                "kind": "recognize",
                "protocol_version": 1,
                "request": malformed,
            }
            with self.subTest(request_id=malformed["request_id"]), self.assertRaises(
                protocol.ProtocolError
            ):
                protocol.dispatch_verified_recognition_request(
                    malformed_frame,
                    handshake_claims=claims,
                    processor=lambda checked: processed.append(checked),
                )
        self.assertEqual(processed, [])

        wrong_fingerprint = {
            **recognize,
            "request": {
                **request,
                "provider_configuration_fingerprint": "provider-config-v1-fnv64-"
                + "0" * 16,
            },
        }
        with self.assertRaises(protocol.ProtocolError):
            protocol.dispatch_verified_recognition_request(
                wrong_fingerprint,
                handshake_claims=claims,
                processor=lambda checked: processed.append(checked),
            )
        changed_config = {
            "configuration_id": "operator-approved-config",
            "values": {"language-mode": "dictation"},
        }
        changed_request = {
            **recognize,
            "request": {
                **request,
                "provider_configuration": changed_config,
                "provider_configuration_fingerprint": protocol.provider_configuration_fingerprint(
                    changed_config
                ),
            },
        }
        with self.assertRaises(protocol.ProtocolError):
            protocol.dispatch_verified_recognition_request(
                changed_request,
                handshake_claims=claims,
                processor=lambda checked: processed.append(checked),
            )
        wrong_id_config = {
            "configuration_id": "other-config",
            "values": {"language-mode": "recognize"},
        }
        wrong_id_request = {
            **recognize,
            "request": {
                **request,
                "provider_configuration": wrong_id_config,
                "provider_configuration_fingerprint": protocol.provider_configuration_fingerprint(
                    wrong_id_config
                ),
            },
        }
        with self.assertRaises(protocol.ProtocolError):
            protocol.dispatch_verified_recognition_request(
                wrong_id_request,
                handshake_claims=claims,
                processor=lambda checked: processed.append(checked),
            )
        self.assertEqual(processed, [])

    def test_handshake_claim_shapes_and_phase_versions_are_checked(self) -> None:
        configuration = fixture_configuration()
        fingerprint = protocol.provider_configuration_fingerprint(configuration)
        handshake = {
            "kind": "handshake",
            "protocol_version": 1,
            "provider_id": "local-reference",
            "configuration_id": "operator-approved-config",
            "configuration_fingerprint": fingerprint,
        }
        for bad in (
            {**handshake, "protocol_version": True},
            {**handshake, "protocol_version": 1.0},
            {**handshake, "protocol_version": "1"},
            {**handshake, "provider_id": ""},
            {**handshake, "configuration_id": ""},
            {**handshake, "configuration_fingerprint": "0" * 16},
        ):
            with self.subTest(frame=bad), self.assertRaises(protocol.ProtocolError):
                protocol.validate_handshake_request(bad)

    def test_recognition_before_handshake_is_rejected(self) -> None:
        recognize = {
            "kind": "recognize",
            "protocol_version": 1,
            "request": {},
        }
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_recognition_request(
                recognize, handshake_claims=None
            )


class OneShotRasterSessionTests(unittest.TestCase):
    def call_session(
        self,
        input_stream: io.BytesIO,
        processor,
    ) -> tuple[io.BytesIO, list[dict[str, object]]]:
        output = io.BytesIO()
        processed: list[dict[str, object]] = []

        def recording_processor(request: dict[str, object]) -> str:
            processed.append(request)
            return processor(request)

        protocol.run_one_shot_raster_session(
            input_stream,
            output,
            provider_identity=fixture_provider_identity(),
            capabilities=fixture_capabilities(),
            provider_provenance="synthetic protocol fixture",
            processor=recording_processor,
        )
        return output, processed

    def assert_rejected_before_processor(
        self,
        input_stream: io.BytesIO,
    ) -> io.BytesIO:
        output = io.BytesIO()
        processed: list[dict[str, object]] = []
        with self.assertRaises(protocol.ProtocolError):
            protocol.run_one_shot_raster_session(
                input_stream,
                output,
                provider_identity=fixture_provider_identity(),
                capabilities=fixture_capabilities(),
                provider_provenance="synthetic protocol fixture",
                processor=lambda request: processed.append(request) or "unused",
            )
        self.assertEqual(processed, [])
        return output

    def test_handshake_then_recognition_emits_exact_text_response_echo(self) -> None:
        request = fixture_raster_request()
        stream = run_session_input(request)
        output, processed = self.call_session(stream, lambda _request: "synthetic raw text")
        self.assertEqual(processed, [request])

        output.seek(0)
        handshake = protocol.read_json_frame(output, protocol.MAX_HANDSHAKE_FRAME_BYTES)
        response = protocol.read_json_frame(output, protocol.MAX_RESPONSE_FRAME_BYTES)
        self.assertIsNone(
            protocol.read_json_frame(output, protocol.MAX_RESPONSE_FRAME_BYTES)
        )
        self.assertEqual(handshake["kind"], "handshake")
        self.assertEqual(handshake["configuration_id"], request["provider_configuration"]["configuration_id"])
        self.assertEqual(
            handshake["configuration_fingerprint"],
            request["provider_configuration_fingerprint"],
        )
        result = response["result"]
        self.assertEqual(result["request_id"], request["request_id"])
        self.assertEqual(result["input_view_id"], request["input_view_id"])
        self.assertEqual(result["source_revision"], request["source_revision"])
        self.assertEqual(result["region_id"], request["region_id"])
        self.assertEqual(result["line_id"], request["line_id"])
        self.assertEqual(result["provider_configuration_id"], "operator-approved-config")
        self.assertEqual(result["provider"], fixture_provider_identity())
        self.assertEqual(result["provider_provenance"], "synthetic protocol fixture")
        self.assertEqual(
            result["provider_configuration_fingerprint"],
            request["provider_configuration_fingerprint"],
        )
        self.assertEqual(result["consumed_input_modalities"], ["raster"])
        self.assertEqual(result["candidates"][0]["recognized_text"], "synthetic raw text")
        self.assertIsNone(result["candidates"][0]["native_score_raw"])
        self.assertEqual(result["candidates"][0]["stroke_ranges"], [])

    def test_processor_cannot_mutate_original_canonical_sample_provenance(self) -> None:
        request = fixture_raster_request()

        def mutating_processor(processor_request: dict[str, object]) -> str:
            processor_request["samples"].clear()
            return "synthetic raw text"

        output, _processed = self.call_session(
            run_session_input(request), mutating_processor
        )
        self.assertEqual(len(request["samples"]), 1)
        output.seek(0)
        protocol.read_json_frame(output, protocol.MAX_HANDSHAKE_FRAME_BYTES)
        response = protocol.read_json_frame(output, protocol.MAX_RESPONSE_FRAME_BYTES)
        self.assertEqual(response["result"]["source_revision"], request["source_revision"])

    def test_phase_order_and_extra_frames_fail_before_processor(self) -> None:
        request = fixture_raster_request()
        recognize = {
            "kind": "recognize",
            "protocol_version": 1,
            "request": request,
        }
        recognize_first = io.BytesIO(
            protocol.encode_json_frame(recognize, protocol.MAX_REQUEST_FRAME_BYTES)
        )
        self.assert_rejected_before_processor(recognize_first)

        extra = {"kind": "unexpected"}
        self.assert_rejected_before_processor(
            run_session_input(request, extra_request=extra)
        )
        self.assert_rejected_before_processor(io.BytesIO())

        config = fixture_configuration()
        handshake = {
            "kind": "handshake",
            "protocol_version": 1,
            "provider_id": "wrong-static-provider",
            "configuration_id": config["configuration_id"],
            "configuration_fingerprint": protocol.provider_configuration_fingerprint(config),
        }
        self.assert_rejected_before_processor(
            run_session_input(request, handshake=handshake)
        )

        configuration = fixture_configuration()
        valid_handshake = {
            "kind": "handshake",
            "protocol_version": 1,
            "provider_id": "local-reference",
            "configuration_id": configuration["configuration_id"],
            "configuration_fingerprint": protocol.provider_configuration_fingerprint(
                configuration
            ),
        }
        handshake_only = io.BytesIO(
            protocol.encode_json_frame(
                valid_handshake, protocol.MAX_HANDSHAKE_FRAME_BYTES
            )
        )
        output = self.assert_rejected_before_processor(handshake_only)
        output.seek(0)
        self.assertEqual(
            protocol.read_json_frame(output, protocol.MAX_HANDSHAKE_FRAME_BYTES)["kind"],
            "handshake",
        )
        self.assertIsNone(
            protocol.read_json_frame(output, protocol.MAX_RESPONSE_FRAME_BYTES)
        )

    def test_revision_mode_and_png_mismatches_fail_before_processor(self) -> None:
        base = fixture_raster_request()
        mismatches = []

        wrong_journal = copy.deepcopy(base)
        wrong_journal["samples"][0]["stroke"]["journal_id"] = "other-journal"
        mismatches.append(wrong_journal)

        wrong_sequence = copy.deepcopy(base)
        wrong_sequence["source_revision"]["last_sequence"] = 0
        mismatches.append(wrong_sequence)

        wrong_mode = copy.deepcopy(base)
        wrong_mode["requested_input_modalities"] = ["online_strokes", "raster"]
        mismatches.append(wrong_mode)

        changed_config = copy.deepcopy(base)
        changed_config["provider_configuration"]["values"]["language-mode"] = "dictation"
        changed_config["provider_configuration_fingerprint"] = protocol.provider_configuration_fingerprint(
            changed_config["provider_configuration"]
        )
        mismatches.append(changed_config)

        wrong_config_id = copy.deepcopy(base)
        wrong_config_id["provider_configuration"]["configuration_id"] = "other-config"
        wrong_config_id["provider_configuration_fingerprint"] = protocol.provider_configuration_fingerprint(
            wrong_config_id["provider_configuration"]
        )
        mismatches.append(wrong_config_id)

        empty_request_id = copy.deepcopy(base)
        empty_request_id["request_id"] = ""
        mismatches.append(empty_request_id)

        wrong_input_view = copy.deepcopy(base)
        wrong_input_view["input_view_id"] = "input-view-v1-1111111111111111"
        mismatches.append(wrong_input_view)

        wrong_png_dimensions = copy.deepcopy(base)
        wrong_png_dimensions["raster"]["width"] = 2
        mismatches.append(wrong_png_dimensions)

        oversized_png = copy.deepcopy(base)
        oversized_png["raster"]["raw_payload_hex"] = "aa" * (
            protocol.MAX_RASTER_INPUT_BYTES + 1
        )
        mismatches.append(oversized_png)

        for request in mismatches:
            with self.subTest(case=request["request_id"]):
                self.assert_rejected_before_processor(run_session_input(request))


class SenOCRWorkerTests(unittest.TestCase):
    def test_runtime_profile_digest_and_package_normalization_are_stable(self) -> None:
        profile, profile_digest = runtime_profile.load_profile()
        self.assertEqual(profile_digest, runtime_profile.PROFILE_SHA256)
        self.assertEqual(
            hashlib.sha256(runtime_profile.canonical_profile_payload(profile)).hexdigest(),
            profile_digest,
        )
        self.assertEqual(
            senocr.SENOCR_PROVIDER_IDENTITY["resource_version"],
            f"senocr-runtime-profile-v1-sha256-{profile_digest}",
        )
        self.assertIn(profile_digest, senocr.SENOCR_PROVIDER_PROVENANCE)
        self.assertEqual(set(profile), runtime_profile.PROFILE_FIELDS)
        self.assertEqual(profile["schema_version"], 1)
        self.assertEqual(profile["python_version"], "3.13.17")
        self.assertEqual(profile["platform"], "windows-x64")
        self.assertEqual(profile["distribution_count"], 41)
        self.assertEqual(
            runtime_profile.normalize_distribution_name("Pillow"), "pillow"
        )
        self.assertEqual(
            runtime_profile.normalize_distribution_name("Typing_Extras"),
            "typing-extras",
        )

    def test_runtime_profile_rejects_missing_extra_duplicate_and_wrong_versions(self) -> None:
        profile, _profile_digest = runtime_profile.load_profile()
        expected = [
            (item["name"], item["version"])
            for item in profile["installed_distribution_closure"]
        ]
        runtime_profile.validate_installed_distribution_closure(profile, expected)
        invalid_closures = [
            expected[:-1],
            expected + [("unprofiled-package", "1.0.0")],
            expected + [expected[0]],
            [
                (name, "0.0.0" if name == "torch" else version)
                for name, version in expected
            ],
        ]
        for closure in invalid_closures:
            with self.subTest(package_count=len(closure)), self.assertRaises(
                runtime_profile.RuntimeProfileError
            ):
                runtime_profile.validate_installed_distribution_closure(
                    profile, closure
                )

    def configuration(self) -> dict[str, object]:
        return {
            "configuration_id": senocr.EXPECTED_PROVIDER_CONFIGURATION_ID,
            "values": {
                "model_id": senocr.MODEL_REPOSITORY,
                "model_revision": senocr.MODEL_REVISION,
                "asset_root": r"C:\Example\Models\SenOCR-Vi",
            },
        }

    def test_config_is_exactly_pinned_and_path_is_local_absolute(self) -> None:
        config = self.configuration()
        self.assertEqual(
            str(senocr.validate_senocr_provider_configuration(config)),
            config["values"]["asset_root"],
        )
        invalid = []
        extra_key = copy.deepcopy(config)
        extra_key["values"]["unexpected"] = "value"
        invalid.append(extra_key)
        wrong_revision = copy.deepcopy(config)
        wrong_revision["values"]["model_revision"] = "other-revision"
        invalid.append(wrong_revision)
        relative_root = copy.deepcopy(config)
        relative_root["values"]["asset_root"] = r"models\SenOCR-Vi"
        invalid.append(relative_root)
        network_root = copy.deepcopy(config)
        network_root["values"]["asset_root"] = r"\\server\share\SenOCR-Vi"
        invalid.append(network_root)
        for candidate in invalid:
            with self.subTest(configuration=candidate), self.assertRaises(
                protocol.WorkerFailure
            ):
                senocr.validate_senocr_provider_configuration(candidate)

    def test_exact_allowlist_and_safetensors_single_shard_policy(self) -> None:
        senocr.validate_asset_inventory_names(set(senocr.MODEL_FILES))
        with self.assertRaises(protocol.WorkerFailure):
            senocr.validate_asset_inventory_names(set(senocr.MODEL_FILES) | {"model.py"})
        with self.assertRaises(protocol.WorkerFailure):
            senocr.validate_asset_inventory_names(
                set(senocr.MODEL_FILES) - {senocr.MODEL_WEIGHT_SHARD}
            )

        valid_index = json.dumps(
            {
                "weight_map": {
                    "layer.weight": senocr.MODEL_WEIGHT_SHARD,
                    "layer.bias": senocr.MODEL_WEIGHT_SHARD,
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(senocr.validate_safetensors_index_payload(valid_index), 2)
        invalid_index = json.dumps(
            {"weight_map": {"layer.weight": "nested/" + senocr.MODEL_WEIGHT_SHARD}},
            separators=(",", ":"),
        ).encode("utf-8")
        with self.assertRaises(protocol.WorkerFailure):
            senocr.validate_safetensors_index_payload(invalid_index)
        with self.assertRaises(protocol.WorkerFailure):
            senocr.validate_safetensors_index_payload(
                b"x" * (senocr.MAX_INDEX_BYTES + 1)
            )

    def test_bounded_file_hashing_matches_git_blob_and_raw_sha256(self) -> None:
        content = b"synthetic test bytes only"
        expected_git_blob = hashlib.sha1(
            f"blob {len(content)}\0".encode("ascii") + content
        ).hexdigest()
        self.assertEqual(
            senocr.hash_asset_stream(
                io.BytesIO(content), len(content), git_blob_sha1=True
            ),
            expected_git_blob,
        )
        self.assertEqual(
            senocr.hash_asset_stream(
                io.BytesIO(content), len(content), git_blob_sha1=False
            ),
            hashlib.sha256(content).hexdigest(),
        )
        with self.assertRaises(protocol.WorkerFailure):
            senocr.hash_asset_stream(
                io.BytesIO(content), len(content) + 1, git_blob_sha1=False
            )

    def test_loading_info_rejects_missing_wrong_typed_or_nonempty_categories(self) -> None:
        senocr._validate_loading_info(
            {
                "missing_keys": set(),
                "unexpected_keys": set(),
                "mismatched_keys": set(),
                "error_msgs": [],
            }
        )
        malformed = (
            {"missing_keys": set(), "unexpected_keys": set(), "mismatched_keys": set()},
            {
                "missing_keys": [],
                "unexpected_keys": set(),
                "mismatched_keys": set(),
                "error_msgs": [],
            },
            {
                "missing_keys": set(),
                "unexpected_keys": set(),
                "mismatched_keys": {"sentinel"},
                "error_msgs": [],
            },
        )
        for loading_info in malformed:
            with self.subTest(loading_info=loading_info), self.assertRaises(
                protocol.WorkerFailure
            ):
                senocr._validate_loading_info(loading_info)

    def test_generated_token_cap_accepts_boundary_and_preserves_decode_text(self) -> None:
        senocr._validate_generated_token_count(senocr.MAX_GENERATED_TOKENS)
        with self.assertRaises(protocol.WorkerFailure):
            senocr._validate_generated_token_count(senocr.MAX_GENERATED_TOKENS + 1)

        class GeneratedTokens:
            def __getitem__(self, key):
                self.key = key
                return "token tail"

        class Processor:
            def batch_decode(self, tokens, **kwargs):
                self.tokens = tokens
                self.kwargs = kwargs
                return ["  raw   decoded\ttext  "]

        generated = GeneratedTokens()
        processor = Processor()
        text = senocr._decode_generated_text(processor, generated, 7)
        self.assertEqual(text, "  raw   decoded\ttext  ")
        self.assertEqual(
            generated.key,
            (slice(None, None, None), slice(7, None, None)),
        )
        self.assertEqual(
            processor.kwargs,
            {"skip_special_tokens": True, "clean_up_tokenization_spaces": False},
        )

    def test_exact_generation_cap_requires_actual_configured_eos(self) -> None:
        synthetic_eos_id = 23

        class ScalarTokenId:
            def __init__(self, value):
                self.value = value

            def item(self):
                return self.value

        class GeneratedSequence:
            def __init__(self, last_token_id):
                self.shape = (1, 5 + senocr.MAX_GENERATED_TOKENS)
                self.last_token_id = last_token_id

            def __getitem__(self, index):
                self.asserted_index = index
                return ScalarTokenId(self.last_token_id)

        completed = GeneratedSequence(synthetic_eos_id)
        senocr._validate_generation_termination(
            completed, 5, [synthetic_eos_id, 29]
        )
        self.assertEqual(completed.asserted_index, (0, 260))

        timed_or_length_limited = GeneratedSequence(17)
        with self.assertRaises(protocol.WorkerFailure):
            senocr._validate_generation_termination(
                timed_or_length_limited, 5, [synthetic_eos_id, 29]
            )

        with self.assertRaises(protocol.WorkerFailure):
            senocr._validate_generation_termination(GeneratedSequence(17), 5, None)

    def test_missing_pillow_maps_to_runtime_failure_before_decode(self) -> None:
        raster = fixture_raster_request()["raster"]

        def missing_pillow():
            raise ImportError("synthetic missing runtime")

        with self.assertRaises(protocol.WorkerFailure) as raised:
            senocr._decode_png_rgb(raster, image_loader=missing_pillow)
        self.assertEqual(raised.exception.code, "runtime_version_mismatch")

    def test_static_png_policy_rejects_animation_before_verify_or_load(self) -> None:
        raster = fixture_raster_request()["raster"]

        class FakeImage:
            format = "PNG"
            size = (1, 1)
            mode = "RGBA"

            def __init__(self, animated, frame_count, info, mime_type):
                self.is_animated = animated
                self.n_frames = frame_count
                self.info = info
                self.mime_type = mime_type
                self.verify_called = False
                self.load_called = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def get_format_mimetype(self):
                return self.mime_type

            def verify(self):
                self.verify_called = True

            def load(self):
                self.load_called = True

        for animated, frame_count, info, mime_type in (
            (True, 2, {}, "image/apng"),
            (False, 2, {}, "image/png"),
            (False, 1, {"default_image": True}, "image/png"),
            (False, 1, {}, "image/apng"),
        ):
            with self.subTest(
                animated=animated, frame_count=frame_count, info=info, mime_type=mime_type
            ):
                fake_image = FakeImage(animated, frame_count, info, mime_type)

                class FakePillow:
                    @staticmethod
                    def open(_stream):
                        return fake_image

                with self.assertRaises(protocol.WorkerFailure) as raised:
                    senocr._decode_png_rgb(raster, image_loader=lambda: FakePillow)
                self.assertEqual(raised.exception.code, "raster_decode_failed")
                self.assertFalse(fake_image.verify_called)
                self.assertFalse(fake_image.load_called)

    def test_truncated_unsupported_color_and_nonopaque_alpha_are_rejected(self) -> None:
        raster = fixture_raster_request()["raster"]
        original_payload = bytes.fromhex(raster["raw_payload_hex"])

        unsupported_color = copy.deepcopy(raster)
        unsupported_payload = bytearray(original_payload)
        unsupported_payload[25] = 3
        unsupported_color["raw_payload_hex"] = unsupported_payload.hex()

        loader_called = False

        def unexpected_loader():
            nonlocal loader_called
            loader_called = True
            raise AssertionError("unsupported color type must fail before Pillow")

        with self.assertRaises(protocol.WorkerFailure) as raised:
            senocr._decode_png_rgb(unsupported_color, image_loader=unexpected_loader)
        self.assertEqual(raised.exception.code, "raster_decode_failed")
        self.assertFalse(loader_called)

        truncated = copy.deepcopy(raster)
        truncated["raw_payload_hex"] = original_payload[:-16].hex()

        class RejectTruncatedImage:
            @staticmethod
            def open(_stream):
                raise OSError("synthetic truncated PNG")

        with self.assertRaises(protocol.WorkerFailure) as raised:
            senocr._decode_png_rgb(truncated, image_loader=lambda: RejectTruncatedImage)
        self.assertEqual(raised.exception.code, "raster_decode_failed")

        class AlphaChannel:
            @staticmethod
            def getextrema():
                return (254, 255)

        class FakeOpaqueCheckImage:
            format = "PNG"
            size = (1, 1)
            is_animated = False
            n_frames = 1
            info = {}
            mode = "RGBA"

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            @staticmethod
            def get_format_mimetype():
                return "image/png"

            @staticmethod
            def verify():
                return None

            @staticmethod
            def load():
                return None

            @staticmethod
            def getchannel(_name):
                return AlphaChannel()

        class FakePillow:
            @staticmethod
            def open(_stream):
                return FakeOpaqueCheckImage()

        with self.assertRaises(protocol.WorkerFailure) as raised:
            senocr._decode_png_rgb(raster, image_loader=lambda: FakePillow)
        self.assertEqual(raised.exception.code, "raster_decode_failed")

    def test_injected_pipeline_decodes_before_loader_and_fails_without_fake_text(self) -> None:
        request = fixture_raster_request()
        configuration = self.configuration()
        request["provider_configuration"] = configuration
        request["provider_configuration_fingerprint"] = protocol.provider_configuration_fingerprint(
            configuration
        )
        stages = []

        def verify_assets(_root):
            stages.append("assets")

        def check_resources():
            stages.append("resources")

        def check_runtime_versions():
            stages.append("runtime")

        def decode_png(_raster):
            stages.append("decode")
            return object()

        def fail_loader(_root):
            stages.append("load")
            raise protocol.WorkerFailure("model_load_failed")

        def generate_text(_runtime, _image):
            stages.append("generate")
            raise AssertionError("generation must not run after model-load failure")

        with self.assertRaises(protocol.WorkerFailure):
            senocr._execute_senocr_pipeline(
                request,
                asset_verifier=verify_assets,
                resource_guard=check_resources,
                runtime_guard=check_runtime_versions,
                image_decoder=decode_png,
                model_loader=fail_loader,
                generator=generate_text,
            )
        self.assertEqual(
            stages,
            ["resources", "runtime", "assets", "decode", "resources", "load"],
        )

    def test_runtime_mismatch_fails_before_assets_or_png_decode(self) -> None:
        request = fixture_raster_request()
        configuration = self.configuration()
        request["provider_configuration"] = configuration
        request["provider_configuration_fingerprint"] = protocol.provider_configuration_fingerprint(
            configuration
        )
        stages = []

        def runtime_mismatch():
            stages.append("runtime")
            raise protocol.WorkerFailure("runtime_version_mismatch")

        with self.assertRaises(protocol.WorkerFailure) as raised:
            senocr._execute_senocr_pipeline(
                request,
                asset_verifier=lambda _root: stages.append("assets"),
                resource_guard=lambda: stages.append("resources"),
                runtime_guard=runtime_mismatch,
                image_decoder=lambda _raster: stages.append("decode"),
                model_loader=lambda _root: stages.append("load"),
                generator=lambda _runtime, _image: stages.append("generate"),
            )
        self.assertEqual(raised.exception.code, "runtime_version_mismatch")
        self.assertEqual(stages, ["resources", "runtime"])

    def test_senocr_e2e_context_guard_precedes_resource_asset_and_model_callbacks(self) -> None:
        stages = []

        def reject_e2e_context():
            stages.append("context")
            raise protocol.WorkerFailure("runtime_version_mismatch")

        def resource_guard():
            stages.append("resources")

        def asset_verifier(_root):
            stages.append("assets")

        def image_decoder(_raster):
            stages.append("decode")

        def model_loader(_root):
            stages.append("load")

        def request_processor(_request):
            resource_guard()
            asset_verifier(Path("synthetic-asset-root"))
            image_decoder({})
            model_loader(Path("synthetic-asset-root"))
            return "unreachable"

        with self.assertRaises(protocol.WorkerFailure) as raised:
            senocr._run_after_senocr_e2e_context_guard(
                {},
                context_guard=reject_e2e_context,
                request_processor=request_processor,
            )
        self.assertEqual(raised.exception.code, "runtime_version_mismatch")
        self.assertEqual(stages, ["context"])

    @unittest.skipUnless(
        os.environ.get("LASSOINK_RUN_SENOCR_M4_E2E") == "1",
        "real Pillow image checks run only in the guarded hosted worker job",
    )
    def test_hosted_pillow_rejects_apng_truncated_palette_and_transparent_png(self) -> None:
        require_senocr_hosted_e2e_guard(self)
        from PIL import Image

        frame_one = Image.new("RGBA", (128, 128), (10, 20, 30, 255))
        frame_two = Image.new("RGBA", (128, 128), (40, 50, 60, 255))
        apng_stream = io.BytesIO()
        frame_one.save(
            apng_stream,
            format="PNG",
            save_all=True,
            append_images=[frame_two],
            duration=20,
            loop=0,
        )
        default_image_stream = io.BytesIO()
        Image.new("RGBA", (128, 128), (5, 15, 25, 255)).save(
            default_image_stream,
            format="PNG",
            save_all=True,
            append_images=[frame_one, frame_two],
            default_image=True,
            duration=20,
            loop=0,
        )
        transparent_stream = io.BytesIO()
        Image.new("RGBA", (1, 1), (10, 20, 30, 254)).save(
            transparent_stream, format="PNG"
        )
        palette_stream = io.BytesIO()
        Image.new("P", (1, 1), 0).save(palette_stream, format="PNG")
        static_stream = io.BytesIO()
        Image.new("RGB", (1, 1), (1, 2, 3)).save(static_stream, format="PNG")

        payloads = [
            (apng_stream.getvalue(), 128, 128),
            (default_image_stream.getvalue(), 128, 128),
            (static_stream.getvalue()[:-16], 1, 1),
            (palette_stream.getvalue(), 1, 1),
            (transparent_stream.getvalue(), 1, 1),
        ]
        apng_fixture = Path(os.environ.get("LASSOINK_SENOCR_APNG_FIXTURE", ""))
        runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
        self.assertTrue(apng_fixture.is_absolute() and runner_temp.is_absolute())
        self.assertTrue(
            apng_fixture.name == "senocr-apng-negative.png"
            and apng_fixture.parent.resolve() == runner_temp.resolve()
            and len(payloads[1][0]) <= 64 * 1024
            and not apng_fixture.exists()
            and not apng_fixture.is_symlink(),
            "APNG fixture path or byte bound is invalid",
        )
        with apng_fixture.open("xb") as apng_file:
            apng_file.write(payloads[1][0])
        for payload, width, height in payloads:
            raster = copy.deepcopy(fixture_raster_request()["raster"])
            raster["width"] = width
            raster["height"] = height
            raster["raw_payload_hex"] = payload.hex()
            with self.subTest(payload_size=len(payload)), self.assertRaises(
                protocol.WorkerFailure
            ) as raised:
                senocr._decode_png_rgb(raster)
            self.assertEqual(raised.exception.code, "raster_decode_failed")

    def test_typed_worker_failure_is_a_bounded_m4_failure_frame(self) -> None:
        request = fixture_raster_request()
        for failure_code in (
            "asset_directory_invalid",
            "runtime_version_mismatch",
        ):
            with self.subTest(failure_code=failure_code):
                output = io.BytesIO()

                def fail_for_test(_request):
                    raise protocol.WorkerFailure(failure_code)

                protocol.run_one_shot_raster_session(
                    run_session_input(request),
                    output,
                    provider_identity=fixture_provider_identity(),
                    capabilities=fixture_capabilities(),
                    provider_provenance="synthetic protocol fixture",
                    processor=fail_for_test,
                )
                output.seek(0)
                self.assertEqual(
                    protocol.read_json_frame(
                        output, protocol.MAX_HANDSHAKE_FRAME_BYTES
                    )["kind"],
                    "handshake",
                )
                failure = protocol.read_json_frame(
                    output, protocol.MAX_RESPONSE_FRAME_BYTES
                )
                self.assertEqual(failure["kind"], "failure")
                self.assertEqual(failure["code"], failure_code)
                self.assertNotIn("C:\\", failure["message"])
                self.assertNotIn("Example", failure["message"])
                self.assertIsNone(
                    protocol.read_json_frame(
                        output, protocol.MAX_RESPONSE_FRAME_BYTES
                    )
                )


class SenOCRWorkerEntrypointTests(unittest.TestCase):
    def test_main_keeps_frames_on_stdout_and_sanitizes_incidental_text(self) -> None:
        frame_stream = io.BytesIO()
        diagnostic_stream = io.StringIO()
        expected_frame = protocol.encode_json_frame(
            {
                "kind": "failure",
                "protocol_version": 1,
                "code": "test_failure",
                "message": "test only",
            },
            protocol.MAX_RESPONSE_FRAME_BYTES,
        )

        def injected_worker(_input_stream, output_stream):
            print("private model path C:\\Example\\models and text")
            sys.stdout.buffer.write(b"unframed diagnostic bytes")
            output_stream.write(expected_frame)

        status = senocr.main(
            input_stream=io.BytesIO(),
            frame_stream=frame_stream,
            diagnostic_stream=diagnostic_stream,
            worker=injected_worker,
        )
        self.assertEqual(status, 0)
        self.assertEqual(frame_stream.getvalue(), expected_frame)
        self.assertEqual(
            diagnostic_stream.getvalue(), "worker diagnostic output suppressed\n"
        )
        self.assertNotIn("Example", diagnostic_stream.getvalue())
        self.assertNotIn("text", diagnostic_stream.getvalue())

    def test_main_returns_sanitized_nonzero_for_protocol_failure(self) -> None:
        frame_stream = io.BytesIO()
        diagnostic_stream = io.StringIO()

        def invalid_worker(_input_stream, _output_stream):
            raise protocol.ProtocolError("private path C:\\Example\\model")

        status = senocr.main(
            input_stream=io.BytesIO(),
            frame_stream=frame_stream,
            diagnostic_stream=diagnostic_stream,
            worker=invalid_worker,
        )
        self.assertEqual(status, 1)
        self.assertEqual(frame_stream.getvalue(), b"")
        self.assertEqual(diagnostic_stream.getvalue(), "worker_protocol_error\n")
        self.assertNotIn("Example", diagnostic_stream.getvalue())

    @unittest.skipUnless(
        os.environ.get("LASSOINK_RUN_SENOCR_M4_E2E") == "1",
        "absolute-path child launch runs only in the guarded hosted worker job",
    )
    def test_absolute_script_path_imports_protocol_from_unrelated_cwd(self) -> None:
        require_senocr_hosted_e2e_guard(self)
        interpreter = Path(sys.executable).resolve(strict=True)
        script = Path(senocr.__file__).resolve(strict=True)
        workspace = script.parent.parent.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="senocr-worker-cwd-") as unrelated_cwd:
            unrelated_cwd_path = Path(unrelated_cwd).resolve(strict=True)
            self.assertFalse(
                unrelated_cwd_path == workspace or workspace in unrelated_cwd_path.parents,
                "temporary worker cwd must be outside the repository",
            )
            child_environment = os.environ.copy()
            child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
            child_environment.pop("PYTHONPATH", None)
            child_environment.pop("PYTHONHOME", None)
            completed = subprocess.run(
                [str(interpreter), str(script)],
                cwd=unrelated_cwd_path,
                env=child_environment,
                input=b"",
                capture_output=True,
                timeout=15,
                check=False,
            )
        self.assertTrue(completed.returncode == 1, "absolute worker child returned an unexpected status")
        self.assertTrue(completed.stdout == b"", "worker emitted non-protocol stdout")
        self.assertTrue(
            completed.stderr == ("worker_protocol_error" + os.linesep).encode("ascii"),
            "worker child did not return the sanitized protocol error",
        )


if __name__ == "__main__":
    unittest.main()
