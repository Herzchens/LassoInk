"""Pure tests for the optional stdlib Raster worker protocol frontend."""

from __future__ import annotations

import copy
import io
import json
import unittest
import zlib
from pathlib import Path

from tools import raster_reference_protocol as protocol


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


if __name__ == "__main__":
    unittest.main()
