# Platform shell selection

Status: implemented discovery and supervised native execution, under review. Owner: TinyBox.
Implementation sequence: [shell selection plan](../plans/shell-selection.md).

## Problem and boundary

A host must discover the module machine's shell syntax without linking TinyBox
implementation crates or returning environment values. Shell selection does
not execute code, approve access, or claim confinement. Native shell execution
uses the module-owned output and cleanup supervisor.

## Contract

Contract 1.10 appends SelectShell(SelectShellRequest) -> ShellInvocation.
The request carries command text and preserve_pipeline_status, default false.
The result carries flavor, program, ordinary arguments, optional Windows raw
arguments, and bootstrap environment variable names.

Unix selects /usr/bin/bash or /bin/bash when present, otherwise sh. Both use
non-login -c; Bash also uses -p to ignore imported environment functions. Bash prepends "set -o pipefail" unless preservation is requested;
sh never receives that Bash-only prefix. For "false | true", Bash's default
selection reports the failing stage; preservation retains the last-stage status.

Windows selects cmd with /D /E:ON /V:OFF /S /C. /D suppresses registry AutoRun. /S strips
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
- Hosts execute behavior through the compiled module. Contract 1.11 appends
  StartShellExec(SpawnRequest, SelectShellRequest) -> ProcessRef. The spawn
  command supplies the resource, cwd, environment and stdin with empty argv.
- StartShellExec supports local passthrough resources only and rejects other
  providers before consuming the process reservation. Selection describes the
  module machine, so its plan cannot be applied to remote hosts or containers.
- It shares StartExec's bounded output journals, request-identity checks,
  cancellation and cleanup barriers. The native builder preserves cmd raw
  arguments through to the supervised child.
- Compiled-module fixtures execute shell text on Unix and quoted executable,
  argument and redirection paths on Windows.

Windows explicitly enables extensions and disables delayed expansion.
Unix builders remove BASH_ENV, ENV, SHELLOPTS and BASHOPTS; ShellInvocation
returns those removal names. Bash uses -p to ignore imported environment
functions. Each discovery probes the standard paths again so shell installation
or removal is reflected immediately. Providers apply them after approved environment overrides.
