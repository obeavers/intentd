# Qualification observed on 2026-11-13

Source: clean Atomic revision `bf9893adb57dccbaa8f7e14277e02d060d74bf53`.
Reference machine: macOS arm64, rustc 1.98.0 (compiler identity in `compiler.log`).

| Claim | Command | Observed result | Evidence |
| --- | --- | --- | --- |
| A1: the full service-layer embedding has a native SQLite dependency conflict | `cargo tree --offline -d --target <target>` in an isolated fixture with real `libatomic`, intentd's SQL dependencies and current intentd lockfile | Exit 101 for each of the four target resolver probes; `rusqlite` requires `libsqlite3-sys` 0.30.1 while intentd requires 0.37.0, both linking `sqlite3` | `report.json`, `resolution-*.log` |
| A2: the standalone dependency boundary builds on macOS arm64 | `cargo build --offline --release --target aarch64-apple-darwin` under toolchain 1.98.0 in the standalone fixture | Passed in 321.691 seconds with real `libatomic` and `atomic-repository` | `native-probe.json`, `build-aarch64-apple-darwin.log` |
| A3: network-denied execution is available on this machine | `sandbox-exec -p '(version 1)(allow default)(deny network*)' <python> -c <socket control>` | Unverified: OS refused sandbox setup with exit 71, `sandbox_apply: Operation not permitted`; the runtime probe was not run | `native-probe.json`, `network-denial-control.log` |

`report.json` comes from the final resolution-only harness run. `native-probe.json`
retains the separately observed native build and containment results. All resolver
probes use the full candidate service-layer dependency; they are not cross builds.
The successful binary is a disposable qualification probe, not a host runtime.
Other release-target builds and full-host no-network behavior remain unverified.

W01 remains open: it still needs the actual host's four-target CI builds and Q4's
fork/upstream owner. A3's complete fixture set belongs to W17. No activation or
runtime fallback is enabled by these results.
