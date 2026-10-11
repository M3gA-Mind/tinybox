use super::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;

#[test]
fn observed_exec_keeps_docker_flags_and_untrusted_argv_separate() -> Result<()> {
    let id = BoxId::new("box-4")?;
    let request = ExecRequest::new(["printf", "%s", "value; touch /tmp/nope"])
        .with_cwd("/workspace/project")
        .with_env("MODE", "two words")
        .with_stdin([0, 255, 1]);

    let observed = exec("team", &id, &request, "a1b2")?;
    let argv = observed.argv;
    assert_eq!(argv[0..3], ["docker", "exec", "-i"]);
    assert_eq!(argv[3..5], ["--workdir", "/workspace/project"]);
    assert_eq!(argv[5..7], ["--env", "MODE=two words"]);
    assert_eq!(argv[7], "tinybox-team-box-4");
    assert_eq!(argv[8..10], ["sh", "-c"]);
    assert!(argv[10].contains("setsid"));
    assert_eq!(argv[11], "tinybox-observed");
    assert_eq!(argv[12], "/tmp/tinybox-observed-a1b2");
    assert_eq!(argv[13..], request.argv);
    assert_eq!(observed.stdin, Some(vec![0, 255, 1]));
    Ok(())
}

#[tokio::test]
async fn supervisor_preserves_binary_pipes_stdin_and_exit_status() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let token = format!("binary-fixture-{}", uuid::Uuid::new_v4().simple());
    let dir = control_dir(&token);
    let cwd = temporary.path();
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg("sh")
        .arg("-c")
        .arg("cat; printf '\\377\\000'; printf '|%s|%s' \"$MODE\" \"$PWD\"; printf 'problem' >&2; exit 7")
        .current_dir(cwd)
        .env("MODE", "observed")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| Error::io("spawn local shell fixture", &error))?;
    let mut stdin = child.stdin.take().ok_or_else(|| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "test observed stdin",
        message: "fixture stdin was not piped".to_owned(),
    })?;
    stdin
        .write_all(&[0, 255, 1])
        .await
        .map_err(|error| Error::io("write fixture stdin", &error))?;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "wait for observed fixture",
            message: "fixture exceeded its deadline".to_owned(),
        })?
        .map_err(|error| Error::io("wait for local shell fixture", &error))?;

    assert_eq!(output.status.code(), Some(7));
    let mut expected_stdout = vec![0, 255, 1, 255, 0];
    expected_stdout.extend_from_slice(format!("|observed|{}", cwd.display()).as_bytes());
    assert_eq!(output.stdout, expected_stdout);
    assert_eq!(output.stderr, b"problem");
    assert!(std::path::Path::new(&dir).join("done").exists());
    let _ = std::fs::remove_dir_all(dir);
    drop(temporary);
    Ok(())
}

#[tokio::test]
async fn supervisor_reaps_leader_and_retires_background_process_group() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let token = format!("background-fixture-{}", uuid::Uuid::new_v4().simple());
    let dir = control_dir(&token);
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("sh")
            .arg("-c")
            .arg(SUPERVISOR)
            .arg("tinybox-observed")
            .arg(&dir)
            .arg("sh")
            .arg("-c")
            .arg("sleep 60 & printf 'leader-finished'")
            .output(),
    )
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "reap background fixture",
        message: "supervisor did not finish process-group cleanup".to_owned(),
    })?
    .map_err(|error| Error::io("run background fixture", &error))?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"leader-finished");
    assert!(std::path::Path::new(&dir).join("done").exists());
    let _ = std::fs::remove_dir_all(dir);
    drop(temporary);
    Ok(())
}

#[tokio::test]
async fn image_without_setsid_refuses_observed_command_before_execution() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let path = temporary.path().join("bin");
    std::fs::create_dir(&path).map_err(|error| Error::io("create fixture path", &error))?;
    std::os::unix::fs::symlink("/bin/mkdir", path.join("mkdir"))
        .map_err(|error| Error::io("link fixture mkdir", &error))?;
    let token = format!("unsupported-fixture-{}", uuid::Uuid::new_v4().simple());
    let dir = control_dir(&token);

    let output = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg("sh")
        .arg("-c")
        .arg("printf 'must-not-run'")
        .env("PATH", path)
        .output()
        .await
        .map_err(|error| Error::io("run unsupported fixture", &error))?;

    assert_eq!(output.status.code(), Some(125));
    assert_eq!(output.stdout, b"");
    assert!(std::path::Path::new(&dir).join("unsupported").exists());
    assert!(std::path::Path::new(&dir).join("done").exists());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn cancellation_waits_for_container_side_waiter_acknowledgement() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let token = format!("cancel-fixture-{}", uuid::Uuid::new_v4().simple());
    let dir = control_dir(&token);
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg("sh")
        .arg("-c")
        .arg("sleep 60")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| Error::io("spawn cancellation fixture", &error))?;

    let pid_path = std::path::Path::new(&dir).join("pid");
    tokio::time::timeout(Duration::from_secs(3), async {
        while !pid_path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "start cancellation fixture",
        message: "supervisor did not publish its process-group identity".to_owned(),
    })?;

    let cleanup = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(CANCEL_AND_ACK)
        .arg("tinybox-observed-cancel")
        .arg(&dir)
        .output()
        .await
        .map_err(|error| Error::io("run cancellation fixture", &error))?;
    assert!(
        cleanup.status.success(),
        "cleanup failed: {}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert_eq!(cleanup.stdout, b"");

    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "reap cancellation fixture",
            message: "supervisor did not exit after acknowledging cleanup".to_owned(),
        })?
        .map_err(|error| Error::io("reap cancellation fixture", &error))?;
    assert_ne!(status.code(), Some(0));
    assert!(!std::path::Path::new(&dir).exists());
    drop(temporary);
    Ok(())
}
