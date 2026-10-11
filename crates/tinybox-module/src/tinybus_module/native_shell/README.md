# Native shell execution

This module prepares caller-approved local shell requests. The retained context
owns the safe environment snapshot, private scratch and a supervised native
collector. It rejects invalid requests before consuming a process reservation.
Resource streams own replay, output budgets, timeout publication and cleanup
barriers. Explicit confinement uses the native jail contract and refuses
unavailable enforcement.

See [the contract](../../../../../docs/specs/native-shell-execution.md) and
[its sequence](../../../../../docs/plans/native-shell-execution.md).
