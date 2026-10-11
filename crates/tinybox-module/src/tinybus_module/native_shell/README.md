# Native shell execution

This module prepares caller-approved local shell requests. The retained context
owns the safe environment snapshot, private scratch and a supervised native
collector. It rejects invalid requests before consuming a process reservation.
Resource streams own replay, output budgets, timeout publication and cleanup
barriers. Explicit confinement uses the native jail contract and refuses
unavailable enforcement.

See [the contract](../../../../../docs/specs/native-shell-execution.md) and
[its sequence](../../../../../docs/plans/native-shell-execution.md).

Output release and resource close explicitly remove private scratch on a
blocking worker after draining the native collector. Timeout and cancellation
drain the process but retain scratch for as long as its journal is retained. A deletion failure is returned to the caller and retains the context
and scratch path for a later cleanup retry.

Preparation runs on Tokio’s blocking pool so filesystem and jail preflight I/O
do not stall the module’s async worker.

Stream admission snapshots shell inputs under the resource lock, releases it
before preparation, and rechecks resource ownership after preparation. Close
and Shutdown can finish while preparation is stalled; late completion cannot
publish an execution for a closed resource.
