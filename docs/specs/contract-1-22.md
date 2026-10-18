# Contract 1.22: native jail resource limits

Contract 1.22 adds the optional `resources` member to `NativeJailConfig`:

```json
{
  "cpu_millis": 500,
  "memory_bytes": 1048576,
  "pids_max": 32,
  "disk_bytes": 10485760
}
```

The fields and units match `tinybox_core::Resources`. When omitted, a request
retains the behavior of contract 1.21. When supplied, all four values must be
positive and each corresponding hard constraint must pass backend preflight.
The native jail currently advertises none of these resource controls, so a
request containing limits is refused before process startup. This contract
addition does not claim to enforce native CPU, memory, process or disk limits.
