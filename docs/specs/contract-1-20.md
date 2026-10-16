# Contract 1.20: native jail read denials

Part of tinyhumansai/openhuman#7819.

Contract 1.20 is a vocabulary bump. It appends no bus member, so `METHODS` is
unchanged. A host that sends a non-empty `deny_read` requires a module minor of
at least 20, which `tinybox_bus::is_compatible` already enforces.

## Added

- `NativeJailConfig::deny_read: Vec<String>`: absolute paths the child may
  neither read nor write, even inside the root or a grant. Serde default empty
  and omitted when empty, so 1.19 requests decode unchanged.
- `JailBackend::carves_denials()`, default `false`: whether a backend can
  subtract a denial from a grant.

## Semantics

- Validated like grants (absolute, no `..`, no NUL, bounded length, counted
  against `MAX_NATIVE_JAIL_GRANTS`). A path that does not exist is dropped; an
  existing one is canonicalized so a symlinked store is denied at its target.
- Refused (`INVALID_FILE_PATH`) when a denial is the root, an ancestor of it, or
  covers a writable grant: the command would have no workspace.
- Refused as unavailable when a denial lies inside the root or a grant and the
  backend cannot carve it out. Outside every grant, allow-list backends
  (Landlock, `AppContainer`) already deny the path.
- Seatbelt reads are allow-default, so the profile ends with
  `(deny file-read* file-write* (subpath ...))`, after the write allows it
  overrides. `subpath` matches a single file as well as a tree.

The host chooses the paths (its credential-store floor); the module only
enforces them.
