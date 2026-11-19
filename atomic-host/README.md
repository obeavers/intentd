# Atomic host qualification

The current-main integration first exercises the **derived recorded-Git query lane**
through an explicitly constructed client. Native source-writing interfaces remain
internal qualification code; their presence does not activate normal workspaces.
The real-process query/reprepare test is `tests/recorded_query_process.rs` and requires
an execution profile that permits Unix IPC.

This separate Rust 1.98 workspace implements the private `intent-atomic-host`
foundation. It does not enable Atomic for user workspaces or link Atomic into
intentd. `upstream.json` records the exact upstream pin; the fork owner remains
unresolved and authoritative activation stays off.

The private protocol exposes handshake, recovery, ping, existing-store open,
state read, close, shutdown, derived recorded-code queries, native tool
classification, and frozen-baseline import, read, materialization and portable
closure calls, plus recorded-target capture and private composition. These are
qualification interfaces; no Atomic workspace capability is advertised. An open never initializes a missing
repository. The explicit Rust initialization and exact-record lifecycle APIs are
journalled and exercised by disposable native fixtures. No authoritative source
recording, composition, publication or sandbox grant capability is advertised.

A native store must match its persisted Intent repository UUID, positive binding
epoch, native directory/database file identities, native project identity and
host pin. One shared `Pristine` handle remains open per cached repository.
Existing-only, non-migrating preflight rejects incomplete native recovery before
the shared-handle constructor runs. Reads use native read transactions without
taking the host writer lane. Joint own/effective state snapshots under concurrent
native source writes remain a gate before those writes are exposed.

Initialization retains an immutable command and separate native identity receipt.
After interruption, a proven native effect can finish its marker and terminal
journal entry. A missing receipt stays uncertain and blocks new admission. This
foundation intentionally provides no automatic adoption or destructive recovery.
The daemon-scoped config, spool, journal and store directories must be private;
store locators are confined beneath the configured `--stores-dir`.

Frozen baselines use an independent full native import per baseline. This is the
explicit storage fallback: previous baselines remain provenance references,
without a mutable parent membership edge or a claim of cheap incremental
storage. Imported Git blob bytes, executable modes and symlink targets are
verified against the native view manifest. Tracked ignored files remain present;
source worktrees and clean/smudge drivers do not supply imported bytes. A tracked
runtime, credential, reserved or explicitly excluded path refuses the import.
The profile is bounded to 50,000 files, 32 MiB per file, 128 MiB total content and
16 MiB of file-manifest metadata. Gitlinks and non-ASCII names on case-folding
destinations remain unqualified and refuse explicitly.

Portable format 2 currently contains only a `FrozenBaseline` component: exact
native change bytes, validated view membership, the native/file manifests, and
the owner scope and allocated capture revision. Restore creates a fresh private
native store, applies exact membership, and verifies materialization without a
source Git checkout, old native cache or database copy. This does not yet
aggregate a live working overlay, selection, authorship boundaries or the
separately versioned work-evidence closure into a complete workspace checkpoint.
The owning Store still controls capture allocation and pointer freshness.

Private composition imports exact native objects into an independent store and
uses native insertion, materialization and conflict capture. The host computes
selected, dependency-only, inherited-baseline, target-context and full closed
membership from the actual graph. Native conflict objects remain binary and
content addressed; typed summaries retain actual path, side hash, kind and mode.
Matching filenames alone do not determine conflicts. The daemon verifies retained
objects, manifests, exact materialized bytes and scope before producing a Rust-only
verified receipt; serialized receipt data cannot confer contribution authority.

Recorded-target capture pins an existing store binding and original native state
in one read snapshot, exports immutable objects, then rechecks the complete cut.
The host retains its capture descriptor before composition. Private reconstruction
verifies root-to-leaf semantic manifests separately: its numeric view IDs may
differ, and its effective state never substitutes for the original source fence.
Without a host-issued capture, only an unchanged frozen-baseline root qualifies.
This does not capture dirty working files, grant a source turn, authorize live
adoption, or qualify conflict-resolution recording, rewind or publication.

The adapted grant facade validates retained native freeze/capture proofs, issues
an actual native registry token and reads bounded recorded files through the
shared store handle. Close revokes admission and drains counted operations;
restart cannot reconstruct a token. Its read basis is the pinned grant manifest,
not a claim about current working files. Source-turn/provider lifecycle and CLI
ingress remain separate gates.

Local triage uses a separate exact-object replica and an explicitly captured
control snapshot, including the four pinned upstream skill/memory defaults.
Unknown control entries refuse. Native report bytes and read pins are retained;
daemon-owned Ed25519 evidence signs those exact values. A native verdict or local
signature does not establish an independent reviewer, task readiness or adoption
authority. No reviewer process is launched by these APIs.

Build and test the real host separately from intentd. Use an external working
directory and the absolute manifest; entering `atomic-host/` would inherit the
parent Cargo configuration. The [packaging recipe](PACKAGING.md) supplies the
independent Cargo home and exact target manifest.

The older Linux qualification runner remains in the preserved source checkpoint.
Its platform/confinement work is separate from this first query integration and
does not enable Atomic workspaces. Unavailable IPC or nested isolation remains a
failed qualification prerequisite.

For ad hoc gates:

```sh
INTENT_ATOMIC_MANIFEST="$(pwd)/atomic-host/Cargo.toml"
cd /tmp
CARGO_HOME=/tmp/intent-atomic-cargo rustup run 1.98.0 cargo check --manifest-path "$INTENT_ATOMIC_MANIFEST" --locked --all-targets
CARGO_HOME=/tmp/intent-atomic-cargo rustup run 1.98.0 cargo test --manifest-path "$INTENT_ATOMIC_MANIFEST" --locked
CARGO_HOME=/tmp/intent-atomic-cargo rustup run 1.98.0 cargo clippy --manifest-path "$INTENT_ATOMIC_MANIFEST" --locked --all-targets -- -D warnings
```

The deterministic 20,000-file import/materialization qualification is ignored
in the normal suite. Run it explicitly in the same isolated environment; it
prints measured durations and does not claim a latency budget from small
functional fixtures:

```sh
CARGO_HOME=/tmp/intent-atomic-cargo rustup run 1.98.0 cargo test --manifest-path "$INTENT_ATOMIC_MANIFEST" --locked baselines::tests::qualification_twenty_thousand_file_baseline_import_and_materialization -- --ignored --exact --nocapture
```

The production manifest and lockfile name the pinned Git source. Offline native
qualification may seed Cargo with the same Git objects from a clean local clone;
that does not change the production dependency declarations. Cross-target builds,
socket/process lifecycle, complete live-workspace/checkpoint recovery, sandbox ingress,
packaging and performance remain separate qualification gates.

Run the reproducible spike from the intentd root with a clean checkout of that
revision:

```sh
python3 scripts/atomic-qualify.py --source /path/to/atomic --output /tmp/atomic-evidence
python3 -I -B -S scripts/test-atomic-qualify.py
```

The output directory must be new. The script verifies the source revision and
clean working tree, never changes that checkout, and creates disposable Cargo
workspaces and build products outside both repositories. It uses only the
installed pinned toolchain and cached Cargo dependencies; it does not fetch
dependencies or install targets. `--skip-build` runs dependency resolution only.

The A1 fixture copies intentd's current lockfile and its actual sqlx and SQLite
dependency declarations alongside `libatomic`. Seeding the lockfile matters:
fresh offline resolution can fail first on an unrelated yanked dependency.
`cargo tree -d` is attempted for each pinned release target. Only Cargo's actual
native SQLite link-conflict diagnostic confirms the conflict; unavailable
packages, tool errors and timeouts remain unverified.

The standalone fixture links real `libatomic` and `atomic-repository` from the
verified source revision and copies Atomic's lockfile. It builds a qualification
binary, using the upstream abort panic model, for the native target by default.
Pass `--build-target` repeatedly to request other installed release targets.
Missing cross toolchains and targets remain unverified. This probe is not the
production host and does not satisfy the four-target host-build exit gate.

After a successful native build, the probe initializes and reopens a disposable
repository under macOS sandbox network denial or a Linux network namespace. A
separate socket control must first prove containment. If the OS cannot establish
containment, the script records an unverified runtime result and does not retry
without it. Configuration uses a temporary `ATOMIC_CONFIG_DIR`; the probe does
not read the user's Atomic identity/configuration directory. This limited
runtime fixture does not establish A3 for the eventual host's providers and
handlers; those fixtures belong to W17.

`report.json` records exact commands, exit codes, durations, input lock hashes,
log hashes, target statuses and remaining work. Logs and the standalone lockfile
are retained beside it. A successful script exit confirms the requested probes,
not completion of W01. W01 stays open until the real host builds in the four
release environments and fork/upstream ownership is assigned. Qualification
must be rerun for every pin bump, including any fork revision carrying durable
change ingress fixes.
