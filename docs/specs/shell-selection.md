# Platform shell selection

Status: implemented discovery contract, under review. Owner: TinyBox.
Implementation sequence: [shell selection plan](../plans/shell-selection.md).

## Problem and boundary

A host must discover the module machine's shell syntax without linking TinyBox
implementation crates or returning environment values. Shell selection does
not execute code, approve access, or claim confinement. Native shell execution
through the module remains a separate required integration slice.

## Contract

Contract 1.10 appends SelectShell(SelectShellRequest) -> ShellInvocation.
The request carries command text and preserve_pipeline_status, default false.
The result carries flavor, program, ordinary arguments, optional Windows raw
arguments, and bootstrap environment variable names.

Unix selects /usr/bin/bash or /bin/bash when present, otherwise sh. Both use
non-login -c. Bash prepends "set -o pipefail" unless preservation is requested;
sh never receives that Bash-only prefix. For "false | true", Bash's default
selection reports the failing stage; preservation retains the last-stage status.

Windows selects cmd with /D /S /C. /D suppresses registry AutoRun. /S strips
exactly one supplied outer wrapper around the raw payload, leaving inner quoted
executable paths, argument pairs and redirection paths intact. Native builders
must use raw_arg for this payload rather than ordinary argument escaping.

Bootstrap results list Windows environment names, including SystemRoot,
COMSPEC and USERPROFILE, without values. The execution provider owns its
approved environment, working directory, pipes and lifecycle.

## Acceptance and constraints

- Wire defaults and method ordering remain backward compatible.
- Selecting a shell never starts a process or returns environment secrets.
- Portable fixtures cover Bash, sh fallback, pipeline preservation and cmd
  argument/wrapper semantics.
- Unix native fixtures exercise pipeline exit statuses.
- Windows native fixtures execute quoted redirection and a quoted executable
  with a quoted argument.
- The actual compiled dynamic module passes production manifest admission and
  executes SelectShell, including when the surrounding test build is static.
- Hosts execute behavior through the compiled module. Existing argv-only
  execution cannot carry cmd raw payloads; its native-shell consumer remains
  an open review requirement, not an implemented capability here.

There are no open decisions for discovery. The pending execution slice must
retain process supervision and prove actual module execution on Windows.
