# Developer T1 tracer

This explicit developer command exercises one Git task, its actual configured
provider, the recorded contribution, the fixed Node test and Atomic's recorded-code
query engine. It then verifies sentinel exclusion and durable reopen. Git remains
source authority. Ordinary Atomic workspaces and native writing stay disabled.

The implementation is awaiting a successful real-provider run on an admitted
execution profile. A passing unit test or failed setup is not T1 acceptance.

## Build and run

Use native macOS ARM64/x64 or Linux x64 GNU/musl with working local IPC, Node,
the normal provider prerequisites and an authenticated provider. Linux aarch64
is not admitted by this runtime profile. Build the daemon tooling and native host
in their separate workspaces:

```sh
cargo build -p intentd --features atomic-tracer --bin atomic-tracer
cargo +1.98.0 build --manifest-path atomic-host/Cargo.toml --bin intent-atomic-host
```

Then run from the daemon repository, choosing a new output path whose parent exists:

```sh
target/debug/atomic-tracer \
  --directory /private/tmp/intent-atomic-t1-001 \
  --host "$PWD/atomic-host/target/debug/intent-atomic-host" \
  --provider codex
```

Use an existing configured adapter id for `--provider`; `--model` is optional.
`--timeout-seconds` defaults to 300 and is bounded to 1–3600. `--node` defaults
to `node`. If CARGO_TARGET_DIR is set, use the binaries in those target directories.
The command is omitted from ordinary builds unless the atomic-tracer feature is
explicitly enabled.

The output path must not already exist, including as a symlink. The command owns
its fixture, daemon database/config/secrets, evidence, provider logs and host data
under that path. It uses the provider's ordinary authentication. It does not open
the installed application's database. Reuse a different output directory for a new
attempt; there is no reset or overwrite mode.

## Acceptance and evidence

A successful run must retain exactly one real provider admission and one Git
contribution. The contribution changes only src/fees.js, makes feeCents(1234,500)
return 62, and leaves the fixed test/package unchanged. The command actually runs
the fixed Node test against a rooted materialization of the recorded commit.

Actual host queries must return the corrected recorded content with matching
repository/root/epoch/commit/tree identities. An uncommitted sentinel must remain
absent. Restart explicitly shuts down and recreates Services and the host, prepares
the same source again, and verifies retained evidence without another provider run
or contribution.

The command writes report.json and report.md and exits nonzero on a failed
scenario, cleanup failure or inability to retain the report. Setup can fail before
the provider starts; for example, this agent execution profile denies Unix socket
binding. Such a result remains failed and must be retried on an admitted profile.

The retained association belongs to Intent. Atomic's read basis remains
ImportedGitSnapshot with null taskRevision. Test observations do not become
independent check receipts, and the report does not claim exclusive authorship,
independent review, source adoption, automatic completion or publication.

## Storage and follow-up integration

The minimum T1 ledger uses SQLite migration 0197 and paired Postgres migration
0007, preserving main's workspace-home migrations. It is deliberately smaller
than the old unmerged 19-migration feature ledger. Later native/review/memory
modules must adapt to this schema or supply a reviewed migration; their old table
names cannot be copied into this branch unchanged.

The first real tracer result, required transport/platform checks and component
review remain gates before deployment. See the monorepo reconciliation execution
record for exact current commands, source commits and remaining blockers.
