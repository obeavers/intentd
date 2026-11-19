# Pinned CLI sandbox compatibility: unqualified

This is source inspection and negative policy qualification. It does not install
skills, expose a listener, grant source access, start a daemon/provider, or qualify
normal Atomic operation. CLI execution and the shared Host transport remain
untested by this inspector.

The exact native revision is `bf9893adb57dccbaa8f7e14277e02d060d74bf53`; the six
unchanged skill resources and original workflow are pinned at
`e9332ebff36f188ed7b7fc31769f661599363184`. The source manifest records fourteen
specific native source hashes. The resource manifest records the exact seven
skill/workflow input hashes. A changed revision, missing input, symlink, changed
source bytes or unrecognized policy structure refuses inspection.

Run only against existing source checkouts:

```sh
python3 -I -B -S scripts/qualify-atomic-cli-sandbox.py \
  --atomic-source /absolute/pinned-atomic-source \
  --skills-source /absolute/pinned-skills-source \
  --output /new/qualification-report.json
```

The report retains hashes of actual inspected inputs, read-only Git command
receipts, derived CLI command prefixes/source lines, native policy tables and
diagnostics. Prefix inventory includes discouraged commands and historical
references; it is not an execution trace or an inferred requirement to run them.
Canonical service routes come from actual generated-client calls in the pinned
source. An absent derived route remains unknown. Remote-pointer CLI commands
fall back to cache bodies, so normal service routes do not establish remote
execution or canonical host writes.

Exit 2 means source incompatibility and/or runtime untested; exit 3 means rejected
inputs. There is no positive override. No CLI command, network connection,
installation, user configuration change or daemon startup is performed.

| Skill | Concrete source findings at the pin |
| --- | --- |
| atomic-vault | Current intent/memory/vault commands exist. Canonical Vault and Attestation routes require independent scope; the native general allowlist is broader than its scoped-handler subset. |
| intent-builder | Its old vault-intent create/show/update/set/add/confirm forms reach removed-command shims declaring exit 2. The inspector does not execute or silently rewrite them. |
| code-intelligence | Query code/search/neighbors/entities and index/reindex forms exist. Knowledge routes are outside the native scoped subset; local-cache or feature-dependent behavior is not qualified. |
| atomic-vcs | Status/log/change/diff use remote-cache bodies and sandbox link primitives. Host framed reads do not implement that CLI transport or its cache bootstrap. |
| decision-record | Memory creation/attestation/validation and vault context require additional canonical scope and signing custody. A source-read token supplies neither. |
| triage-review | Cross-view candidate/report operations and review intents require their own explicit authority; Triage routes are outside native sandbox scoping. |

The current Host grant owner retains its actual native registry, one NativeStore,
and counted in-flight reads until close/drain. Raw upstream SandboxImpl uses
per-request repository opens and cannot join that count. Materialize's path
prefix handling also cannot replace Intent's slash-boundary manifest policy.
Missing token metadata is a native local-caller path; a trusted native grant
extension is not a revocable Host Entry. A provider ingress must therefore require
its genuine retained Host lease before delegating any request, including one
carrying a valid native token. Client DTOs and optional flags supply no proof.

The new native tests exercise actual pinned policy/registry APIs without sockets:
the general/scoped allowlist distinction, unsupported canonical query/triage
routes, read-only capabilities, missing-token local behavior, and copied grant
extension behavior after real registry revocation. They prove these boundaries,
not a working CLI or Host gRPC adapter. The existing CI packaging test entry
loads the mocked source-inspector tests. Actual native tests remain a separate
focused `cli_sandbox_qualification` run owned by the central test runner.

A positive implementation needs the same actual registry and counted admission
owner for both framed and gRPC requests, shared-handle primitives, exact
manifest/inode/change bounds, and queued/cancelled/streaming close/drain evidence.
No source or skill activation is implied by passing this inspection.
