# Contract 1.22: native jail resource limits

Contract 1.22 adds the optional `resources` member to `NativeJailConfig`. It
uses the existing `tinybox_bus::ResourceLimits` type:

```json
{
  "cpu_millis": 500,
  "memory_bytes": 1048576,
  "pids_max": 32,
  "disk_bytes": 10485760
}
```

The fields and units match the `Create` request's resource vocabulary. When
omitted, a request retains the behavior of contract 1.21. When supplied, all
four values must be positive and each corresponding hard constraint must pass
backend preflight, including when the request uses declared enforcement for
filesystem, network, or subprocess policy.

Hosts must bind only to a module advertising contract 1.22 before sending the
new field. Older modules may ignore unknown JSON fields, so sending it without
the compatibility check can silently lose the requested limits. The native
jail currently enforces none of these resource controls; it refuses a request
containing limits before process startup. This addition does not claim to
enforce native CPU, memory, process or disk limits.
