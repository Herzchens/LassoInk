"""Pure tests for the optional stdlib Raster worker protocol frontend."""

from __future__ import annotations

import io
import unittest

from tools import raster_reference_protocol as protocol


def fixture_configuration() -> dict[str, object]:
    # Mirrors the operator-approved fixture in src/provider_protocol.rs:3470.
    return {
        "configuration_id": "operator-approved-config",
        "values": {"language-mode": "recognize"},
    }


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
        configuration = fixture_configuration()
        fingerprint = protocol.provider_configuration_fingerprint(configuration)
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
        request = {
            "protocol_version": 1,
            "provider_configuration": configuration,
            "provider_configuration_fingerprint": fingerprint,
        }
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


if __name__ == "__main__":
    unittest.main()
