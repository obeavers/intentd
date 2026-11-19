# Native record patch candidates

These patches target Atomic commit
`bf9893adb57dccbaa8f7e14277e02d060d74bf53`. They are **not applied** to the
host's pinned Git dependencies. A clean applicability check is not native
compilation, upstream acceptance, crash qualification, or feature activation.

- `0001-explicit-raw-record-policy.patch` adds an explicit raw byte policy to
  record and its status scan. It bypasses attribute lookup, clean/smudge
  conversion, Git config discovery, and external filter drivers. The default
  behavior stays unchanged. Before adopting it, add upstream regression tests
  for CRLF, ident expansion, required drivers, binary files, executable modes,
  symlinks, and recorded-baseline comparisons.
- `0002-durable-unix-ordinary-ingress.patch` reuses Atomic's existing durable
  projected-object publisher for ordinary Unix ingress. It flushes complete
  bytes before no-overwrite publication and refuses a different full envelope
  under an existing native hash. Its compatibility implications for callers
  that update unhashed metadata require upstream review. Windows durability is
  unchanged and remains unqualified for this host.

From a separate clean checkout at that exact commit:

```sh
git apply --check /path/to/0001-explicit-raw-record-policy.patch \
  /path/to/0002-durable-unix-ordinary-ingress.patch
```

The current host instead refuses selected sources with applicable
`.gitattributes` and explicitly fsyncs the verified original object and its
directory ancestors before insertion. Preparation uses a read-only sealed
working-copy database with saving, application, enrichment, indexing and vault
sync disabled. These are bounded qualification APIs, not an enabled Atomic
editing backend.
