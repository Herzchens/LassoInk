# Third-party notices

This file records attribution and license material for the direct DOCX/PDF libraries, the bundled Noto Sans face, and selected transitive packages with additional or nonstandard notice obligations. It is not an exhaustive dependency inventory. `docx-rs` and `printpdf` are regular application dependencies; Markdown/HTML remain the default export selection, while DOCX/PDF are opt-in formats. The PDF serializer embeds a subset of Noto Sans; the DOCX serializer names Noto Sans and does not embed a font.

The repository root [LICENSE](LICENSE) is the project's Apache License 2.0 text. For the dependencies below, source-published license files are preserved separately under `third_party_licenses/`, including package-specific MIT/Apache text and attribution lines. Cargo's slash-form license strings are reproduced as declared; the slash is not interpreted here.

## Direct DOCX/PDF libraries

| Package | Locked checksum | Declared license | License text | Versioned source locator |
| --- | --- | --- | --- | --- |
| `docx-rs 0.4.22` | `7fdf00e8af6d0b3e92d4bbf9b76f773d8b84ea80f310324ad16cbdc2e653e02c` | `MIT` | [MIT](third_party_licenses/MIT-docx-rs.txt) — Copyright (c) 2020 bokuweb | [Published source](https://docs.rs/crate/docx-rs/0.4.22/source/); [license at the published source commit](https://github.com/bokuweb/docx-rs/blob/f04cf8b47a925b2b6fff850dcb75069aae89dab4/LICENSE) |
| `printpdf 0.13.0` | `59188c84413d8fdaf0ca2f3b28a0151bbfa888961be523d314425a594c73e4d5` | `MIT` | [MIT](third_party_licenses/MIT-printpdf.txt) — Copyright (c) 2017 Felix Schütt | [Versioned source](https://github.com/fschutt/printpdf/tree/v0.13.0); [LICENSE](https://github.com/fschutt/printpdf/blob/v0.13.0/LICENSE) |

## Pathfinder geometry

`pathfinder_geometry 0.5.1` is locked with checksum `0b7b7e7b4ea703700ce73ebf128e1450eb69c3a8329199ffbfb9b2a0418e5ad3`. The crate archive is [published by crates.io](https://crates.io/api/v1/crates/pathfinder_geometry/0.5.1/download); its published source is [on docs.rs](https://docs.rs/crate/pathfinder_geometry/0.5.1/source/).

The nine source copyright headers identify The Pathfinder Project Developers: 2020 in `src/angle.rs`; 2019 in `src/lib.rs`, `src/line_segment.rs`, `src/rect.rs`, `src/transform2d.rs`, `src/transform3d.rs`, `src/unit_vector.rs`, `src/util.rs`, and `src/vector.rs`. Their headers offer Apache-2.0 and MIT at the recipient's option; this project selects Apache-2.0. Its complete standard text is supplied in [LICENSE](LICENSE) and [Apache's official license page](https://www.apache.org/licenses/LICENSE-2.0).

## azul-simplecss

`azul-simplecss 0.2.3` is locked with checksum `beea02de84f7d4c090ccf9a2bddcd0595105b35c2ed0c9a0ed66aca4b79559bd`. Its declared license is `MPL-2.0`; its authors are Reizner Evgeniy and Felix Schütt. The [published crate source](https://docs.rs/crate/azul-simplecss/0.2.3/source/) records `fschutt/simplecss` commit `debf5110c88e6077560417e88b3dd60d09264358`, and the crate's `LICENSE.txt` is preserved at [third_party_licenses/MPL-2.0-azul-simplecss.txt](third_party_licenses/MPL-2.0-azul-simplecss.txt).

The published source package is available at [crates.io](https://crates.io/api/v1/crates/azul-simplecss/0.2.3/download), with the corresponding upstream source at [the pinned repository commit](https://github.com/fschutt/simplecss/tree/debf5110c88e6077560417e88b3dd60d09264358). This is a transitive dependency of the production PDF serializer. If a distributed binary includes the MPL-covered code, recipients must be told how to obtain its source as required by MPL-2.0 Sections 3.1–3.2; the versioned published source locator above identifies that code.

## unicode-properties

`unicode-properties 0.1.5` is locked with checksum `993ad287eb20e8ba755312801cfe1413e0f25d604075863acaddca10b04c1833`. Its declared license expression is `(MIT OR Apache-2.0) AND Unicode-3.0`. The [published crate source](https://docs.rs/crate/unicode-properties/0.1.5/source/) records `unicode-rs/unicode-properties` commit `b5594806088d6492327228a74d05c881b9b3c042`.

The crate's `COPYRIGHT` pointer and all three license texts are represented here: [COPYRIGHT](third_party_licenses/COPYRIGHT-unicode-properties.txt), [Apache-2.0](third_party_licenses/APACHE-unicode-properties.txt), [MIT](third_party_licenses/MIT-unicode-properties.txt), and [Unicode License v3](third_party_licenses/Unicode-3.0-unicode-properties.txt). The MIT text attributes The Rust Project Developers (2015); Unicode License v3 attributes Unicode, Inc. (1991–2026).

## brotli-decompressor

`brotli-decompressor 5.0.3` is locked with checksum `3a32acac15fe1967bc3986b2a6347dffc965602354ea6f450ad07e8bfd253583`. Its manifest declares the literal expression `BSD-3-Clause/MIT`; the published crate source is [on docs.rs](https://docs.rs/crate/brotli-decompressor/5.0.3/source/) and records `dropbox/rust-brotli-decompressor` commit `b56177b8eb3d2440536281397e5ffe06eedf1a5c`. The crate's only root license file is BSD-3-Clause, with `Copyright (c) 2016 Dropbox, Inc.`; its full text is preserved at [third_party_licenses/BSD-3-Clause-brotli-decompressor.txt](third_party_licenses/BSD-3-Clause-brotli-decompressor.txt).

The manifest authors list Daniel Reiter Horn and The Brotli Authors, and the crate describes itself as an implementation of Google's Brotli. The associated Google Brotli v1.1.0 source license is MIT, with `Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors`; that text is preserved at [third_party_licenses/MIT-brotli-authors.txt](third_party_licenses/MIT-brotli-authors.txt), with the source notice in [Google's v1.1.0 LICENSE](https://github.com/google/brotli/blob/v1.1.0/LICENSE). The published decompressor crate itself contains no separate `LICENSE-MIT`; this entry keeps the crate's BSD text and the attributed upstream MIT text distinct without interpreting the slash expression.

## Slash-form MIT/Apache package metadata

These newly added locked manifests use slash-form expressions. Both exact source license files are retained for each package; no operator is inferred from the slash.

| Package | Locked checksum | Manifest expression | MIT source text | Apache source text | Source locator |
| --- | --- | --- | --- | --- | --- |
| `core_detect 1.0.0` | `7f8f80099a98041a3d1622845c271458a2d73e688351bf3cb999266764b81d48` | `MIT/Apache-2.0` | The Rust Project Developers (2017–2020); [text](third_party_licenses/MIT-core_detect.txt) | [source text](third_party_licenses/APACHE-core_detect.txt) | [Published source](https://docs.rs/crate/core_detect/1.0.0/source/); upstream commit `a0f957776563806e7d20978471676e0db72892ba` |
| `gl-context-loader 0.1.10` | `5ca63cb2488b847c12d1ca56034ba0f15613972c0dc0f8a957f525707567b23d` | `Apache-2.0/MIT` | Mozilla Foundation (2012–2013); [text](third_party_licenses/MIT-gl-context-loader.txt) | [source text](third_party_licenses/APACHE-gl-context-loader.txt) | [Published source](https://docs.rs/crate/gl-context-loader/0.1.10/source/); upstream commit `b9afdec46b721b054930c5972387055e992300cc` |
| `mmapio 0.9.1` | `0204e2cac68f5b2e35b7ec8cb5d906f6e58e78dad8066a30b6ee54da99bb03dd` | `MIT/Apache-2.0` | Dan Burkert (2015); [text](third_party_licenses/MIT-mmapio.txt) | [source text](third_party_licenses/APACHE-mmapio.txt) | [Published source](https://docs.rs/crate/mmapio/0.9.1/source/); upstream commit `1bbad28d36a0c9677d067a3a08e315865387dccd` |
| `proc-macro2-diagnostics 0.10.1` | `af066a9c399a26e020ada66a034357a868728e72cd426f3adcd35f80d88d88c8` | `MIT/Apache-2.0` | Sergio Benitez (2016–2020); [text](third_party_licenses/MIT-proc-macro2-diagnostics.txt) | [source text](third_party_licenses/APACHE-proc-macro2-diagnostics.txt) | [Published source](https://docs.rs/crate/proc-macro2-diagnostics/0.10.1/source/); upstream commit `45fa2d68669d10daeaf0f9b664a96576626fae16` |
| `rangemap 1.9.0` | `f2d43a8c8c74056248124068fde0df374d1ddf9039e747d190f01c36faeaab08` | `MIT/Apache-2.0` | Jeffrey Parsons (2019); [text](third_party_licenses/MIT-rangemap.txt) | Jeffrey Parsons and contributors (2019–2022); [text](third_party_licenses/APACHE-rangemap.txt) | [Versioned source](https://github.com/jeffparsons/rangemap/tree/v1.9.0); [crate page](https://docs.rs/crate/rangemap/1.9.0) |
| `stringprep 0.1.5` | `7b4df3d392d81bd458a8a621b8bffbd2302a12ffe288a9d931670948749463b1` | `MIT/Apache-2.0` | The rust-stringprep Developers (2017); [text](third_party_licenses/MIT-stringprep.txt) | [source text](third_party_licenses/APACHE-stringprep.txt) | [Published source](https://docs.rs/crate/stringprep/0.1.5/source/); upstream commit `97e2588933017b48122e8bb574efebb7410fa71c` |
| `version_check 0.9.5` | `0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a` | `MIT/Apache-2.0` | Sergio Benitez (2017–2018); [text](third_party_licenses/MIT-version_check.txt) | [source text](third_party_licenses/APACHE-version_check.txt) | [Published source](https://docs.rs/crate/version_check/0.9.5/source/); upstream commit `d77ef9f27cc336719b2d839d09ee6635dd22f758` |
| `winapi 0.3.9` | `5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419` | `MIT/Apache-2.0` | The winapi-rs Developers (2015–2018); [text](third_party_licenses/MIT-winapi.txt) | [source text](third_party_licenses/APACHE-winapi.txt) | [Published source](https://docs.rs/crate/winapi/0.3.9/source/); upstream commit `796a8e6c2971dc2ff1bcff166e6671284f9b5b6b` |
| `xmlparser 0.13.6` | `66fee0b777b0f5ac1c69bb06d361268faafa61cd4682ae064a171c16c433e9e4` | `MIT/Apache-2.0` | Reizner Evgeniy (2018); [text](third_party_licenses/MIT-xmlparser.txt) | [source text](third_party_licenses/APACHE-xmlparser.txt) | [Published source](https://docs.rs/crate/xmlparser/0.13.6/source/); upstream commit `28ce4a6b52c6b4abba07dd7d6c7f8cc39cc842aa` |

## Bundled Noto Sans face

The repository includes the unmodified static Noto Sans Regular v2.015 face at [assets/fonts/NotoSans-Regular.ttf](assets/fonts/NotoSans-Regular.ttf), SHA-256 `478C558EA716033CD60C03438F628DFA75694DCF6B5F6D505A2F05FD2B4F3823`. The font is Copyright 2022 The Noto Project Authors and is distributed under SIL OFL 1.1; the accompanying full notice is [assets/fonts/OFL.txt](assets/fonts/OFL.txt). PDF output embeds a subset of this face. DOCX output sets the font family name but contains no font file. The pinned upstream source is [notofonts/latin-greek-cyrillic at `c4a321e123e4d4ff315f57f4e0adf294fe3a95be`](https://github.com/notofonts/latin-greek-cyrillic/tree/c4a321e123e4d4ff315f57f4e0adf294fe3a95be).
