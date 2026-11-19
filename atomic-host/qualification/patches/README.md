# Native record-start intent freeze

The pinned Atomic revision `bf9893adb57dccbaa8f7e14277e02d060d74bf53`
exports `SessionStore::bind_turn_intent`, but its record-start
`freeze_turn_intent` method is crate-private. Binding alone remains a declared
association. The local `HostFacadeFreezeV1` implementation ports the exact marker
effect under the same native turn lock, with additional original-source journals,
no-follow filesystem checks and durable crash repair. It is an Intent-owned
facade at the unchanged pin; it does not call the private upstream function.

Run host qualification from `packages/intentd` with the same credential-free
embedding environment used by the supervised process:

```sh
env -u VOYAGE_API_KEY -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  cargo +1.98.0 test --manifest-path atomic-host/Cargo.toml --offline --locked --lib
```

The pinned convenience vault writers may automatically resolve external
embedding providers. Local task projection and recovery therefore refuse a
configured ambient provider before vault initialization or entry writes; they never temporarily clear
the process environment. Negative tests use isolated child environments and
deliberately invalid inputs, so even a refusal regression cannot reach a real
embedding call. Private triage copies native rows through transactions and
rebuilds its derived graph without those convenience writers. This policy does
not establish operating-system network containment or close the external-state
qualification gate.

The adjacent patch is a fallback proposal for a public facade that acquires the existing native
turn lock, validates the exact active session/turn/UID, then invokes the existing
durable native freeze. It is a proposal, not an applied dependency patch or a
qualified upstream guarantee. Nothing applies it during builds. The clean source
checkout and the current pin remain unchanged.

If the fallback upstream patch is selected, its qualification must use a separate
disposable checkout at that exact revision. The existing local host facade requires
no dependency patch or fork revision change:

1. Check the patch with `git apply --check` before applying it in that disposable
   checkout. Review the facade against that checkout's actual session types.
2. Add native tests for unknown/inactive/ended sessions, expected-turn mismatch,
   mismatched UID, lock contention, exact replay, and corrupted declaration bytes.
   A frozen turn must reject every later attempt to replace its declared UID,
   including after an attempted record fails or returns no changes.
3. Run the upstream agent session tests and a host fixture that freezes
   immediately before exact native record preparation. Edit the source intent
   after dispatch and prove that the record keeps the selected immutable task
   revision and retained source/canonical/substance pins; it must never substitute
   the mutable current intent's definition or infer governance from file overlap.
4. Inject process exits before and after the durable marker and record journal
   boundaries. Reopen against exact owner evidence. Missing or ambiguous proof
   remains unavailable; a declaration never becomes a frozen acknowledgement.
5. Land the reviewed facade in the selected fork/upstream, update the pinned
   revision and lock/qualification evidence, then implement the actual callable
   host facade and typed recording integration. Requalify all release targets.

The local host facade qualification fixtures exercise real public same-UID binding
before and after the marker, original-source retention after later projection,
failed/no-change record preparation, lock contention, changed marker refusal and
process exit after the durable marker. Their results must be recorded by the
central native gate before claiming qualification of those local mechanics. That
qualification does not establish process transport or operating-system containment.
The daemon authoring pipeline
remains unavailable until its transport, actual capture and execution-grant
owners are composed and qualified. A native freeze does not itself certify task
authority, check execution, candidate adoption or publication.
