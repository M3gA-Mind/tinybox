//! Container-side supervision for observed Docker executions.
//!
//! The shell that owns the Docker exec stays outside the workload session. It
//! waits for the session leader, kills any children the requested command left
//! behind, and writes an acknowledgement only after its wait and group cleanup
//! finish. A separate `docker exec` can request cancellation without treating
//! the Docker CLI's local exit as proof that the container workload stopped.

use tinybox_core::{BoxId, Error, ExecRequest, Result};

use super::{NAME, args};

const CONTROL_ROOT: &str = "/tmp";

/// Run the requested command in its own session and supervise its process group.
///
/// Arguments after `$0` are a private control directory followed by the user's
/// argv. No user value is interpolated into this shell program.
const SUPERVISOR: &str = r#"
set -u
dir=$1
shift
umask 077
mkdir -m 700 "$dir" || exit 125
exec 3<&0
if ! command -v setsid >/dev/null 2>&1; then
  : > "$dir/unsupported"
  : > "$dir/done"
  exit 125
fi

# `setsid` is launched as a background child of a non-job-control shell, so it
# is not a process-group leader and can keep its own PID while creating the
# workload session. The inner shell records that session leader before exec.
setsid sh -c 'printf "%s\\n" "$$" > "$1/pid" || exit 125; shift; exec "$@"' \
  tinybox-observed-child "$dir" "$@" <&3 &
leader=$!

# The watcher has no output handles and remains outside the workload group.
# It sends the cancellation signal; this shell owns wait/reap and the final
# acknowledgement.
(
  while [ ! -f "$dir/cancel" ]; do sleep 0.01; done
  pid=$(cat "$dir/pid" 2>/dev/null) || exit 0
  case "$pid" in ''|*[!0-9]*) exit 0 ;; esac
  kill -KILL "-$pid" 2>/dev/null || :
) </dev/null >/dev/null 2>&1 &
watcher=$!

wait "$leader"
status=$?
kill "$watcher" 2>/dev/null || :
wait "$watcher" 2>/dev/null || :

pid=$(cat "$dir/pid" 2>/dev/null) || pid=
case "$pid" in
  ''|*[!0-9]*) ;;
  *)
    # A successful command may leave background descendants behind. Retire
    # the complete group and wait until the container confirms it is gone. Keep
    # this waiter alive while cleanup is uncertain so a later retry can still
    # receive its reap acknowledgement.
    while kill -0 "-$pid" 2>/dev/null; do
      kill -KILL "-$pid" 2>/dev/null || :
      sleep 0.01
    done
    ;;
esac

printf '%s\\n' "$status" > "$dir/status" || exit 125
: > "$dir/done" || exit 125
exit "$status"
"#;

/// Request remote cancellation and wait for the owning shell's reap marker.
const CANCEL_AND_ACK: &str = r#"
set -u
dir=$1
if [ ! -d "$dir" ]; then exit 1; fi
: > "$dir/cancel" || exit 1
attempt=0
while [ ! -f "$dir/done" ]; do
  if [ "$attempt" -ge 500 ]; then exit 1; fi
  attempt=$((attempt + 1))
  sleep 0.01
done
if [ -f "$dir/unsupported" ]; then printf 'unsupported\\n'; fi
rm -rf "$dir" || exit 1
exit 0
"#;

/// Build a `docker exec -i` request that preserves command arguments and stdin.
pub(super) fn exec(
    namespace: &str,
    id: &BoxId,
    request: &ExecRequest,
    token: &str,
) -> Result<ExecRequest> {
    if request.argv.is_empty() {
        return Err(Error::EmptyCommand {
            sandbox: NAME.to_owned(),
        });
    }

    let directory = control_dir(token);
    let mut argv = vec!["docker".to_owned(), "exec".to_owned(), "-i".to_owned()];
    args::add_exec_context(&mut argv, request);
    argv.push(args::container_name(namespace, id));
    argv.extend([
        "sh".to_owned(),
        "-c".to_owned(),
        SUPERVISOR.to_owned(),
        "tinybox-observed".to_owned(),
        directory,
    ]);
    argv.extend(request.argv.iter().cloned());

    let mut observed = ExecRequest::new(argv);
    if let Some(stdin) = &request.stdin {
        observed = observed.with_stdin(stdin.clone());
    }
    Ok(observed)
}

/// Build a request that asks the remote waiter to kill and reap one workload.
pub(super) fn cancel_and_ack(namespace: &str, id: &BoxId, token: &str) -> ExecRequest {
    ExecRequest::new([
        "docker".to_owned(),
        "exec".to_owned(),
        args::container_name(namespace, id),
        "sh".to_owned(),
        "-c".to_owned(),
        CANCEL_AND_ACK.to_owned(),
        "tinybox-observed-cancel".to_owned(),
        control_dir(token),
    ])
}

/// The token is minted by the provider and contains only UUID hex/hyphen bytes.
fn control_dir(token: &str) -> String {
    format!("{CONTROL_ROOT}/tinybox-observed-{token}")
}

#[cfg(test)]
#[path = "observed_tests.rs"]
mod tests;
