# Experimental host packaging

This integration includes the explicit local build/staging command. Automatic CI,
daemon-release and frontend-payload wiring described below is a later integration
step; these packaging contracts do not mean those pipelines are installed here.

The isolated host is not enabled for normal user workspaces. A built artifact is
not a qualification result or permission to advertise native authority. Native
record/baseline, crash, containment and latency gates retain their own evidence.

The runtime locator is `<intentd executable directory>/libexec/atomic-host/intent-atomic-host`.
A configured explicit executable takes precedence. The host is never found through
`PATH`. An absent executable or an exact private identity mismatch remains
`atomic-unavailable`; existing native workspaces retain read-only snapshot/checkpoint
access where implemented.

From the intentd root, inspect a build without running Cargo:

```sh
python3 -I -B scripts/build-atomic-host.py --target aarch64-apple-darwin \
  --cargo-home /tmp/intent-atomic-cargo --plan
```

Remove `--plan` to perform the actual locked release build after installing the
pinned toolchain and target. The script runs the absolute host manifest from a
fresh external directory with an independent Cargo home. Running Cargo from
`atomic-host/` would inherit intentd's parent `.cargo/config.toml` patches even
though this is a separate workspace, so it is deliberately avoided. The host's
Rust 1.98 toolchain does not replace intentd's pinned compiler or dependencies.

`packaging/libexec/atomic-host/` contains the thin target-specific executable,
Apache-2.0 `LICENSE` and `NOTICE`, upstream pin, and `manifest.json`. The manifest
derives the current private contract/store format from `intent-atomic-proto`,
and records the exact Atomic revision, compiler output, lock/source digests,
target and executable digest. Source changes during a build refuse staging.

The subsequent CI integration should attempt four independent real builds: macOS
arm64/x64 and Linux x86_64 GNU/musl, retaining unsigned qualification payloads. No
Windows host is planned. The current daemon release chain ships Linux musl; GNU
build evidence must not be presented as a shipped daemon archive.

The eventual cargo-dist integration must stage supported host payloads after native
build prerequisites and include them through `packaging/libexec`. Unsupported
Windows/Linux-arm daemon targets must clear any stale host payload. Release-script
wiring is retained in the source checkpoint for that later reviewed change.

The later frontend integration must stage the same relative payload and validate
architecture, exact manifest/upstream pins and hashes; an old daemon archive with
no host must clear stale staged bytes. Its signing hook must sign the host before
the application seal, retaining unsigned and signed executable digests. A successful
signed bundle requires a real release build to exercise that wiring.

## OS network containment recipe

The native arm64 macOS and GNU Linux CI legs run
`scripts/test-atomic-host-contained.py`. It first proves OS denial with an
independent socket control using macOS sandbox policy or a Linux network
namespace. Missing containment, a failed control or `--control-only` exits nonzero
and records `unavailable`; it never retries without the policy or turns a skipped
runtime green. A successful control is followed by separately compiled default
host library/binary test executables under the same policy. Ignored tests remain
excluded and are not implied qualified. Logs and `report.json` are retained even
when the control or handlers refuse/fail.

```sh
python3 -I -B scripts/test-atomic-host-contained.py \
  --cargo-home /tmp/intent-atomic-cargo --target-dir /tmp/intent-atomic-target \
  --output /tmp/new-host-containment-evidence
```

Run offline script regressions with:

```sh
python3 -I -B -S scripts/test-build-atomic-host.py
python3 -I -B -S scripts/test-atomic-host-containment.py
make lint-workflows
make test-release-scripts
```

Synthetic executable headers and mocked containment commands in those unit tests
verify the packaging recipe only. They do not count as native builds, signing or
OS containment evidence. This change has no user-help impact while experimental.
