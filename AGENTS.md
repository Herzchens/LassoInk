# AGENTS.md - LassoInk

Repository execution contract for `Herzchens/LassoInk`.

LassoInk is an open-source Windows handwriting application centered on high-fidelity digital-pen capture, canonical ink preservation, handwriting recognition, provenance, and on-demand conversion into structured digital documents.

This repository is not a general-purpose notebook suite. Do not expand it into one without an explicit product decision.

Before making meaningful implementation changes, read:

- `AGENTS.md`;
- relevant accepted ADRs and public technical documentation;
- the active task contract;
- current source, tests, manifests, CI configuration, and Git history;
- the canonical local planning artifact described below when the task depends on implementation planning.

Do not implement from chat memory when repository or canonical planning evidence is available.

---

## 1. Product boundary

LassoInk exists to support this core flow:

```text
drawing tablet
    ↓
high-fidelity pen capture
    ↓
canonical physical ink history
    ↓
minimal freestyle canvas
    ↓
user requests Convert
    ↓
recognition / interpretation
    ↓
semantic document representation
    ↓
Markdown / HTML / DOCX / PDF / future exports
```

Core value:

1. capture fidelity;
2. preservation of physical ink;
3. recognition accuracy;
4. Vietnamese cursive and delayed-diacritic robustness;
5. provenance;
6. reproducibility;
7. future reinterpretation of old ink using newer recognizers.

LassoInk is not currently intended to become:

- a full OneNote/Xournal++/Rnote replacement;
- a collaborative notebook platform;
- a cloud-sync service;
- a full PDF editor;
- a general vector drawing application;
- an AI agent workspace;
- a model-training platform.

Do not add those surfaces merely because they are adjacent to handwriting.

---

## 2. Authority and conflict resolution

When sources conflict, use this order:

1. non-overridable platform, tool, security, data-integrity, and user-safety constraints;
2. newest explicit project-owner decision;
3. hard invariants in this `AGENTS.md`;
4. canonical local planning artifact when relevant;
5. accepted ADRs;
6. active task contract;
7. repository contracts and executable tests;
8. older research/planning evidence;
9. convenience.

Current code and tests are evidence of current behavior, not automatic product truth.

A plan is not automatically correct because it is detailed.

A filename containing `FINAL`, `REVISED`, `UPDATED`, or similar wording does not prove that its contents are current.

### Owner override

The owner may deliberately override a repository rule.

An override is valid only when:

1. the owner explicitly identifies the relevant rule or behavior to override;
2. material consequences are explained;
3. the owner confirms the override when those consequences are non-trivial.

Do not infer an override from casual wording such as `just do it`, `ship it`, or similar language.

An override applies only to the stated scope and creates no permanent precedent.

Platform/system/tool safety constraints are outside repository-level override authority.

---

## 3. External planning artifact

The canonical LassoInk implementation plan is a **local-only planning artifact**.

It MUST NOT enter Git-tracked repository history or GitHub.

The expected local location is:

```text
local_document/
└── Plan.md
```

A different root-level ignored `local_*` directory may be used when explicitly approved, but there must be one identifiable canonical planning copy for an implementation run.

Its physical presence inside the working tree does not make it a repository artifact.

It must remain:

- ignored;
- untracked;
- uncommitted;
- unpushed.

`local_document/` itself must be ignored by Git.

The plan is a read-only implementation input unless the owner explicitly asks to update it.

Before executing an implementation package that depends on the plan, the coordinator must ensure that the newest canonical `Plan.md` is available and identifiable for that run.

If the required canonical planning artifact is:

- unavailable;
- stale;
- contradictory;
- accidentally tracked;
- accidentally committed;
- impossible to identify confidently;

then:

- fail closed for plan-dependent implementation;
- do not guess from memory;
- do not reconstruct an AI handoff inside the repository;
- do not create replacement planning documents from chat history;
- restore or obtain the authoritative planning artifact first.

Public repository documentation must describe **implemented behavior and public architecture**, not mirror the private planning document by habit.

If a planning decision becomes an enduring public architectural contract, promote only that accepted decision into an appropriate public ADR or technical document.

---

## 4. Skepticism and evidence

Do not assume that any of the following are automatically correct:

- the task prompt;
- the local plan;
- previous AI research;
- existing implementation;
- tests;
- README claims;
- dependency documentation;
- benchmark headlines;
- model cards;
- comments in old issues;
- the owner;
- this file.

Challenge assumptions when material evidence conflicts with them.

### Evidence states

For significant technical findings, use one of:

```text
CONFIRMED
DISPROVED
UNRESOLVED
```

A suspicion from static review is not automatically a bug.

To treat a bug as `CONFIRMED`, establish enough evidence for the type of failure involved, preferably including:

- the exact affected code path;
- the expected contract or invariant;
- a concrete failure path;
- relevant callers and guards;
- reproduction or a regression test where practical.

Do not change semantics merely to fix an unconfirmed theory.

Serious unresolved capture, corruption, data-loss, concurrency, privacy, or licensing risks may be hardened defensively when the hardening does not invent unsupported product behavior, but reports must still distinguish evidence from inference.

---

## 5. Research discipline

LassoInk depends on mutable Windows APIs, device drivers, Rust crates, commercial SDKs, ML models, and research implementations.

For claims that affect architecture, prefer:

```text
official/current documentation
    ↓
actual source / exact artifact
    ↓
exact issue / PR / review
    ↓
original paper
    ↓
maintainer statement
    ↓
model card / README
    ↓
secondary source
```

Do not:

- infer behavior from a filename;
- infer an entire repository license from a badge or one manifest;
- infer model rights from source-code rights;
- infer current SDK internals from an old research paper;
- infer current behavior from stale search snippets;
- infer correctness from star count;
- infer recognition quality from runtime-parity tests;
- treat "I could not find it" as "it does not exist".

When checking mutable software, record exact version, tag, commit, issue, PR, or date when materially relevant.

If a current fact cannot be verified, mark it unresolved instead of filling the gap from memory.

---

## 6. Plan is a hypothesis, not proof

The local `Plan.md` is the current implementation baseline, not a command to implement every idea it contains.

Before each meaningful implementation slice:

1. inspect current repository state;
2. identify assumptions in the plan;
3. compare them with current source and evidence;
4. check platform/stdlib/existing dependencies for simpler solutions;
5. identify the smallest implementation that proves the next required property.

If new evidence invalidates a planning assumption:

- do not blindly continue;
- do not silently invent a replacement architecture;
- explain the conflict;
- propose the smallest justified deviation;
- obtain an owner decision when the deviation changes architecture or project semantics;
- update the local planning artifact only when explicitly authorized.

Prefer:

```text
platform / standard library
→ existing repository implementation
→ existing well-supported dependency
→ small adaptation
→ hybrid
→ custom subsystem only when justified
```

Novelty is not a project objective.

---

## 7. Gate discipline

LassoInk is intentionally evidence-gated.

Do not implement later-stage sophistication merely because it appears in long-term research.

The intended progression is:

```text
Gate 0: capture fidelity
    ↓
canonical journal + replay
    ↓
minimal canvas
    ↓
provider boundary
    ↓
single-provider bake-off
    ↓
first useful Convert
    ↓
measured failure analysis
    ↓
only then optional R&D gates
```

Current deferred/gated work includes:

- Temporal Repair;
- multi-provider fusion;
- CTC/stroke-ID raster alignment;
- full reversible Scene Graph;
- large personalization models;
- custom Vietnamese recognizer;
- dual-modal in-house model;
- Math AST pipeline;
- VLM adjudication;
- Merkle-heavy archival infrastructure.

Do not create production implementations of these before their prerequisite gate is satisfied.

Explicitly requested prototypes are allowed, but they must remain isolated and must not silently become the production path.

---

## 8. Gate 0 is mandatory

The first architecture decision is capture fidelity on real hardware.

Primary device:

```text
XPPen Deco Fun XS / CT430
```

Current known device assumptions include:

- approximately 4.8 × 3 inch active area;
- 5080 LPI;
- 8192 nominal pressure levels;
- approximately 220 RPS maximum nominal report rate;
- approximately 10 mm reading height;
- no tilt support on the XS model.

Do not turn nominal specifications into measured runtime facts.

### Required capture candidates

At minimum compare:

```text
Windows Ink ON
    ├─ direct WM_POINTER history
    └─ public windowing abstraction

Windows Ink OFF
    └─ Wintab path
```

Add RealTimeStylus only when the primary paths are inconclusive.

Do not open Raw HID work unless measured evidence shows that higher-level APIs discard information required by the product.

### Hardware evidence rule

Synthetic fixtures can test parsing, ordering, serialization, and failure handling.

Synthetic fixtures cannot prove:

- actual CT430 sampling rate;
- PT_PEN behavior;
- Windows Ink behavior;
- Wintab fidelity;
- pressure fidelity;
- driver coalescing;
- hardware jitter;
- reconnect behavior.

Do not report Gate 0 as passed without real-device evidence.

---

## 9. Capture invariants

Canonical pen capture must preserve physical evidence faithfully.

Never silently:

- interpolate canonical samples;
- synthesize missing samples;
- duplicate samples to approximate a higher report rate;
- use render frames as pen samples;
- replace missing pressure with guessed values;
- fabricate native timestamps;
- infer tilt on CT430;
- reorder physical strokes to improve recognition.

If a native API returns history in reverse order, explicit tested chronological normalization is allowed.

### Timestamp integrity

Preserve the highest-quality native timestamp available.

Where native pointer timing such as `POINTER_INFO.PerformanceCount` is available, do not replace it with application arrival time.

Application monotonic arrival time may be stored separately.

Never mix clocks without an explicit conversion contract.

### Input/render separation

Render FPS must never determine canonical pen sample frequency.

A stalled renderer must not silently discard recoverable input history.

### API transitions

Do not silently fall back:

```text
WM_POINTER → mouse
WM_POINTER → Wintab
Wintab → mouse
```

without recording the transition or failing visibly where required.

### Configuration drift

Tablet mapping may change because the CT430 is also used by other applications.

Record sufficient session metadata, including where available:

- tablet model;
- driver version;
- Windows Ink state;
- active area;
- mapped display;
- pressure curve;
- Windows build;
- input API;
- session identity.

A material configuration change must not silently remain part of the same assumed measurement environment.

---

## 10. Unsafe Rust and Windows FFI

Windows capture may require `unsafe`.

`unsafe` is permitted when required by platform FFI but must remain localized.

Prefer:

```text
small unsafe Win32 boundary
        ↓
validated owned Rust representation
        ↓
safe internal API
```

Every non-trivial unsafe block must carry a meaningful safety justification.

Review:

- pointer lifetime;
- buffer sizing;
- message lifetime;
- handle ownership;
- callback/thread affinity;
- structure initialization;
- integer conversions;
- timestamp units;
- array ordering;
- API invalidation after queue advancement.

Do not leak raw Win32 pointers or handles throughout unrelated UI/domain code.

---

## 11. Canonical ink is source of truth

Physical ink history is canonical.

Recognition is derived.

Rendering is derived.

Semantic interpretation is derived.

Exported documents are derived.

Original physical pen samples must not be destructively rewritten during normal editing.

Operations such as:

- erase;
- move;
- logical delete;
- correction;
- regrouping;

must be represented as revision/edit state unless an explicit destructive feature is later designed.

Every recognition result must reference its source revision and relevant source region/strokes.

Recognition must not become canonical truth because a model is confident.

User corrections are separate evidence and must not rewrite physical ink history.

---

## 12. Journal invariants

The journal must support:

- deterministic replay;
- crash recovery;
- schema evolution;
- logical edits;
- source revision identity;
- future re-recognition.

Snapshots are accelerators, not canonical history.

A corrupt or deleted snapshot must be reconstructible from the supported canonical journal history.

Do not add Merkle trees, distributed event infrastructure, or elaborate compaction before measured scale/integrity requirements justify them.

Regression coverage should include:

- valid replay;
- truncated final record;
- malformed record;
- snapshot + tail replay;
- schema-version handling;
- logical deletion/revisions.

---

## 13. External ink formats

Wacom UIM, InkML, DOCX ink, and similar formats may be useful for interoperability.

They are not automatically the canonical journal format.

Default:

```text
LassoInk canonical journal
        ↓
materialized/interchange representation
        ↓
UIM / other formats when useful
```

Do not replace the canonical journal with an interchange format unless an explicit architecture decision proves that required raw capture, revision, provenance, and replay semantics survive.

---

## 14. Recognition provider boundary

The open-source core must remain functional without proprietary recognition providers.

Without recognition installed, implemented core functionality should still support:

- capture;
- persistence;
- replay;
- canvas rendering;
- editing;
- project open/save.

Recognition providers should default to a subprocess/worker boundary unless evidence justifies another mechanism.

This supports isolation of:

- C++ SDKs;
- Python;
- GPU/CUDA;
- model crashes;
- independent provider updates;
- optional proprietary dependencies.

This is a technical isolation decision.

Do not claim it automatically resolves licensing obligations.

Provider adapters must not own canonical state.

Provider failure must not corrupt ink or fabricate success.

---

## 15. Recognition provenance

Where available retain:

- source revision;
- source region;
- source stroke IDs/ranges;
- provider;
- provider version;
- model/resource version or hash;
- input representation/view;
- candidates;
- candidate rank;
- native score;
- relevant runtime configuration.

Do not call an arbitrary model score a calibrated probability without calibration evidence.

---

## 16. Recognition-family independence

Implementation diversity is not recognition-model diversity.

If official ML Kit, `mlkit-ink`, and `ink-rs` use materially the same Google model family, do not count them as separate independent recognition sources in Oracle/fusion analysis.

Do not artificially inflate ensemble diversity.

---

## 17. No premature fusion

Do not implement multi-provider fusion merely because multiple providers exist.

Measure independent families first.

Compute the raw-provider Oracle.

If Oracle performance is negligibly better than the best single provider, stop.

Fusion becomes eligible only when:

- providers exhibit useful error complementarity;
- Oracle headroom is meaningful relative to uncertainty;
- an actual selector produces positive net gain;
- rescue materially exceeds harm;
- latency remains acceptable.

Expanded candidate sets alone are not evidence of improvement.

---

## 18. Temporal Repair is virtual only

Physical chronology must never change to satisfy a recognizer.

If Temporal Repair is later opened:

```text
canonical physical order
        ↓
virtual inference views
```

Do not brute-force arbitrary permutations.

Evaluate independently:

```text
provider(raw)
vs
provider(raw + repaired view)
```

Measure delayed and non-delayed subsets separately.

An improved Oracle without actual automatic gain does not justify shipping it.

---

## 19. Raster recognition

Raster HTR is a challenger, not an automatic fallback.

A published VNOnDB benchmark does not prove performance on CT430 natural notes.

Evaluate:

- public benchmark quality;
- device-native quality;
- out-of-domain behavior;
- character coverage;
- preprocessing/aspect-ratio handling;
- latency;
- runtime/model availability.

Record provider-specific preprocessing as part of the recognition input view.

---

## 20. Render-mediated stroke alignment

CTC/stroke-ID alignment is deferred R&D.

Do not implement it in v1 unless fine-grained provenance becomes a measured product requirement that existing providers cannot satisfy.

If opened later:

- render visual and provenance surfaces through identical geometry;
- account for resize and padding;
- do not treat CTC spikes as exact glyph boundaries;
- account for cursive overlap and Vietnamese diacritics;
- report approximate alignment honestly.

---

## 21. Personalization

Personalization may precede fusion if writer-specific errors dominate.

Prefer cheaper mechanisms first:

```text
personal lexicon
→ exact correction memory
→ reusable correction patterns
→ stroke/glyph prototypes
→ writer representation
→ adapter/fine-tuning
```

Evaluation must use future sessions.

Do not validate adaptation on samples it already learned from.

---

## 22. Vietnamese evaluation

Vietnamese recognition is a primary requirement.

Evaluation must include more than generic CER/WER.

Relevant classes include:

- cursive/connected writing;
- tone marks;
- vowel modifiers;
- delayed diacritics;
- delayed `i` dots;
- delayed cross strokes;
- syllable/word boundaries;
- fast notes;
- abbreviations;
- Vietnamese-English mixed writing;
- technical identifiers.

Character-by-character segmentation must not become the default path without evidence.

---

## 23. Benchmark integrity

Use at least:

```text
public Vietnamese benchmark
+
CT430 controlled corpus
+
CT430 natural-note corpus
```

Public datasets are useful for reproducibility but are not the sole product benchmark.

Avoid leakage.

Use as appropriate:

- writer-disjoint;
- session-disjoint;
- time-disjoint;
- configuration-disjoint.

Do not randomly split same-session lines and claim independent generalization.

Use paired provider evaluation on identical samples and clustered uncertainty estimates where observations are correlated.

---

## 24. Dependencies and toolchain

Before adding a direct dependency:

1. identify the exact problem;
2. check platform/stdlib/current implementation;
3. inspect maintenance state;
4. inspect license and relevant transitive impact;
5. inspect current stable release and relevant changelog;
6. justify its layer and necessity.

Use stable releases by default.

Do not select beta/RC/nightly merely because the number is newer.

Do not perform unrelated dependency churn during feature work.

Do not hand-edit lockfiles to fake dependency resolution.

ML/GPU/Python dependencies should remain outside the minimal core unless explicitly justified.

---

## 25. Scope discipline

Make the smallest complete change satisfying the active task.

Do not silently:

- redesign the architecture;
- change storage format;
- replace capture APIs;
- replace GUI framework;
- switch recognition families;
- introduce cloud/network services;
- introduce telemetry;
- add accounts;
- mass-format unrelated files;
- upgrade unrelated dependencies;
- perform unrelated cleanup;
- expand product scope.

Report important adjacent findings separately.

Do not hide behavior changes inside refactors.

---

## 26. Repository hygiene

Treat unknown working-tree changes as belonging to someone else until provenance is established.

Do not overwrite or delete them for convenience.

Never commit repository-local AI diary or handoff files.

Examples:

```text
CODEX_PROGRESS.md
AI_NOTES.md
CHATGPT_HANDOFF.md
TEMP_RESEARCH.md
```

The canonical `local_document/Plan.md` is also strictly local-only.

Durable public project state belongs in:

- signed commits;
- PRs;
- Issues;
- accepted ADRs;
- intentionally maintained public documentation;
- intentionally versioned benchmark/evidence artifacts.

Temporary local evidence and scratch outputs remain untracked.

Do not commit build caches or release binaries as source artifacts unless explicitly designed otherwise.

---

## 27. Branch discipline

Never push implementation directly to `main` unless the owner explicitly authorizes that exact workflow.

Branches describe work, not the AI/tool.

Format:

```text
<type>/<short-kebab-description>
```

Examples:

```text
feat/win32-capture-probe
feat/canonical-journal
fix/history-ordering
refactor/provider-protocol
test/journal-crash-recovery
docs/capture-gate
```

Forbidden names include:

```text
codex/*
chatgpt/*
claude/*
gemini/*
agent/*
ai/*
bot/*
gpt/*
```

---

## 28. Every commit must be signed

**Every commit created for LassoInk must carry a valid cryptographic Git signature using the owner's approved signing identity.**

This applies to:

- feature commits;
- fix commits;
- test commits;
- docs commits;
- CI commits;
- refactors;
- temporary development commits that are actually committed;
- merge/rebase replacement commits;
- initial/bootstrap commits;
- release preparation commits.

There is no allowed "unsigned temporary commit now, sign later" workflow during normal repository development.

If an agent needs temporary experimentation without signing capability, keep changes uncommitted or use another local mechanism that does not create repository commits.

### Signing source

The project is authored from the owner's machine and commit identity/signing configuration must use the owner's approved local Git signing setup.

Agents must not:

- generate an unrelated signing identity;
- substitute their own key;
- disable signing to make a commit succeed;
- use `--no-gpg-sign`;
- claim a commit is signed without verifying it.

Before committing, inspect the existing repository/user Git signing configuration rather than replacing it blindly.

Expected policy includes the equivalent of:

```text
commit.gpgsign = true
```

using the owner's configured signing mechanism.

The exact signing backend may be SSH, GPG, or another Git-supported mechanism selected by the owner.

### Signing failure

If signing fails:

1. stop before creating an unsigned commit;
2. preserve the worktree;
3. diagnose the signing environment;
4. report the blocker;
5. repair the approved signing path or leave the changes uncommitted for the owner.

Never downgrade the repository to unsigned history merely to continue automation.

### Verification

After each commit, verify its signature through the available Git verification path.

Before PR/merge/release, verify the complete commit range intended to land.

Do not assume a commit is trusted merely because GitHub renders a green UI badge without understanding what identity/key produced it.

### History rewriting

If a commit is rewritten, the replacement commit must also be signed.

A successful signature on the old commit does not carry over to its replacement SHA.

Do not destroy another contributor's valid signed history merely for cosmetic history cleanup.

---

## 29. Commit discipline

Use Conventional Commits in English:

```text
feat(scope): description
fix(scope): description
refactor(scope): description
perf(scope): description
test(scope): description
docs(scope): description
ci(scope): description
chore(scope): description
```

Each commit must be coherent and reviewable.

Final history must not contain noise such as:

```text
wip
fix again
debug
try test
oops
temp
review fix 2
```

Because every commit must be signed, prefer doing exploratory work in the worktree and committing only coherent units.

Do not create commits merely to trigger CI.

If several temporary signed development commits become one logical unit, history may be rewritten before review only when safe to do so; every replacement commit must itself be signed.

Do not force-push shared history that another contributor has already based work on without explicit coordination.

---

## 30. Pull requests

Use focused PRs.

PR descriptions should explain:

- what changed;
- why;
- important architecture/behavior implications;
- validation performed;
- unresolved risk.

Do not put execution diaries or internal AI reasoning in public PR descriptions.

Never write:

```text
As an AI...
The user asked me...
Codex decided...
ChatGPT thinks...
```

The repository owner/contributor identity is the public project identity.

Do not create or merge a PR unless the active task allows it.

Never merge solely because CI is green.

Before merge, verify:

- final diff;
- required tests;
- exact final SHA;
- signature validity of every commit being introduced;
- no accidental local planning artifacts are tracked.

---

## 31. Self-review is mandatory

After implementation and before completion:

1. read the entire final diff;
2. compare it with the active task and invariants;
3. inspect edge cases;
4. inspect failure paths;
5. inspect tests;
6. inspect documentation claims;
7. inspect dependencies;
8. inspect platform assumptions;
9. verify no gated feature was introduced;
10. verify clean signed history.

For capture/storage/provider work specifically review:

- ordering;
- duplicate handling;
- timestamp units;
- integer conversion;
- partial writes;
- crash recovery;
- thread safety;
- lifetime/handle ownership;
- retry/idempotency;
- silent fallback;
- provenance loss;
- stale revision use.

A green compiler is not a review.

A green suite is not proof of hardware fidelity.

---

## 32. Exact-final-head verification

Verification belongs to the exact commit being reviewed or merged.

Any:

- amend;
- rebase;
- formatter change;
- generated-file change;
- conflict resolution;
- self-review fix;
- dependency-lock change;

changes the final SHA and invalidates earlier final-head verification.

Run required gates again.

Because rewriting also replaces signatures, verify the new final commit signatures again after every history rewrite.

Never claim hosted CI passed without inspecting the run for the exact final SHA.

---

## 33. Testing expectations

Once the Rust workspace exists, the default quality floor should include repository-equivalent commands such as:

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
```

Use the exact repository-defined commands once CI/tooling is established.

Windows-specific capture functionality requires Windows validation.

Do not claim capture correctness from platform-independent unit tests.

Important test classes include:

- deterministic journal replay;
- serialization round-trip;
- truncated/corrupt recovery;
- history ordering normalization;
- deduplication logic;
- timestamp conversion;
- provider protocol compatibility;
- provider crash/timeout;
- stale source revisions;
- recognition provenance;
- correction separation;
- benchmark metric correctness.

Mocks do not replace Gate 0.

---

## 34. CI behavior

CI verifies source.

CI must not silently rewrite and push source merely to make itself green.

Do not grant write permissions just for formatting or automatic source fixes.

Prefer read-only/fail-fast validation.

Keep CI permissions minimal.

If release/signing infrastructure becomes privileged, isolate it from untrusted PR code.

CI success does not prove:

- real CT430 behavior;
- recognition accuracy;
- licensing validity;
- privacy correctness;
- architecture correctness.

---

## 35. Licensing boundaries

LassoInk core is licensed separately from external recognition assets.

Always separate:

```text
source code
model weights
dataset
SDK/runtime
model download/mirror
```

Never reason:

```text
crate is Apache-2.0
therefore model weights are Apache-2.0
```

or:

```text
public download URL
therefore redistribution is permitted
```

or:

```text
subprocess boundary
therefore copyleft/proprietary obligations disappear
```

Do not ship proprietary SDKs, model weights, or questionable mirrors by default.

Prefer optional BYO-SDK/BYO-Model integration where rights are unresolved.

Escalate material licensing ambiguity before packaging/releases.

This section is engineering risk policy, not legal advice.

---

## 36. Secrets and user data

Never commit:

- SDK license keys;
- API keys;
- auth tokens;
- private signing keys;
- private certificates;
- user handwriting corpora not explicitly approved for publication;
- personal notes;
- local benchmark data containing private content.

Raw ink, timing, pressure, corrections, and handwriting may contain personal or biometric-like information.

Treat them as sensitive user data.

Diagnostics must not casually upload handwriting.

Network transmission of canonical ink requires an explicit product decision and visible user behavior.

---

## 37. Privacy-first default

Core capture and journaling are local-first.

Recognition providers must explicitly declare when they require:

- network access;
- cloud processing;
- authentication;
- handwriting upload.

Do not silently send handwriting to remote services.

Offline and cloud provider behavior must remain distinguishable.

---

## 38. UI discipline

The canvas exists to support handwriting and Convert.

Prioritize:

- low-latency writing;
- clear selection;
- predictable editing;
- visible recognition state;
- easy correction;
- provenance-aware interaction;
- accessibility;
- Windows-native expectations where useful.

Avoid unnecessary dashboard/product chrome.

Do not let visual polish compromise capture isolation.

Do not redesign the entire product while implementing a capture/storage/provider slice.

---

## 39. Performance measurement

Measure rather than infer when practical.

Capture measurements may include:

- effective sample frequency;
- event/history counts;
- timestamp delta distribution;
- p50/p95/p99 intervals;
- duplicate rate;
- drop indicators;
- pressure distribution;
- positional jitter;
- capture latency;
- CPU overhead.

Recognizer measurements include:

- CER/WER;
- Vietnamese-specific error metrics;
- p50/p95/p99 latency;
- model load time;
- RAM;
- VRAM;
- CPU/GPU utilization;
- determinism.

Benchmark reports must identify:

- dataset/subset;
- split;
- provider/model version;
- preprocessing;
- hardware where relevant.

---

## 40. No fake completion

Do not claim completion because:

- an interface exists;
- a stub returns success;
- a mock passes;
- one happy-path test passes;
- code compiles;
- CI is green;
- a paper claims the approach works.

Do not leave reachable production paths returning fake success.

Do not swallow failures.

Do not substitute guessed defaults for invalid canonical input.

Fail explicitly when continuation would corrupt or misrepresent canonical state.

---

## 41. Release discipline

LassoInk is intended to ship Windows executable releases.

Release artifacts should come from a defined release process, not source-history commits.

Before release:

- run required CI on the exact release commit;
- verify Windows behavior;
- verify commit signatures;
- verify provider packaging and licenses;
- verify no private planning documents, corpus data, credentials, or secrets are bundled;
- inspect package contents;
- document experimental providers/features;
- verify release notes against shipped behavior.

Release notes describe user-visible changes relative to the previous release, not implementation history.

Release tags must be signed using the owner's approved signing identity.

Do not publish an unsigned release tag.

Do not claim reproducible builds, code signing, model authenticity, or cryptographic verification unless actually implemented and checked.

---

## 42. Architecture changes

Major architecture changes include:

- changing journal semantics;
- replacing the capture path;
- changing source-of-truth ownership;
- making recognition canonical;
- adding mandatory cloud processing;
- replacing worker isolation with mandatory in-process ML/proprietary runtimes;
- unlocking fusion before evidence;
- making a custom model mandatory;
- changing privacy defaults;
- breaking project-format compatibility.

For such changes:

1. inspect current evidence;
2. explain why the existing decision no longer holds;
3. compare alternatives;
4. obtain the required owner decision;
5. update the canonical local plan when explicitly requested;
6. promote durable public architecture decisions into an ADR where appropriate;
7. document migration/compatibility effects.

Do not hide architecture changes inside unrelated PRs.

---

## 43. Completion report

When finishing work, report concisely:

- final behavior/change;
- exact validation performed;
- tests/checks unavailable or not run;
- real-hardware validation performed or still required;
- signature verification performed;
- remaining known risk;
- `UNRESOLVED` findings;
- owner decisions still required.

Do not provide a terminal diary unless asked.

Do not claim `production-ready`, `fully verified`, or equivalent without matching evidence.

---

## 44. Final principle

When several implementations are correct, prefer the one that is:

- easier to understand;
- easier to verify;
- smaller in hidden behavior;
- clearer about failure modes;
- easier to replay and debug;
- easier to maintain;
- less coupled to one recognition provider;
- less likely to destroy or silently reinterpret canonical evidence.

For LassoInk, sophistication is earned by measured failure.

Do not implement complexity before proving the simpler path is insufficient.
