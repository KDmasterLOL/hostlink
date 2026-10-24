use std::{
	process::Stdio,
	time::{Duration, Instant},
};

use tokio::io::{AsyncBufReadExt, BufReader};

use super::prelude::*;

const DESCENDANT_MARKER: &str = "PW-DESCENDANT:";
const LAUNCH_DESCENDANT: &str = r#"$p=Start-Process powershell.exe -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Milliseconds 1500' -PassThru; Write-Output ('PW-DESCENDANT:' + $p.Id); exit 0"#;

#[tokio::test]
async fn job_waits_for_descendant_after_launcher_exit() -> Result<()> {
	let mut command = CommandWrap::with_new("powershell.exe", |command| {
		command
			.args([
				"-NoLogo",
				"-NoProfile",
				"-NonInteractive",
				"-Command",
				LAUNCH_DESCENDANT,
			])
			.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
	});
	command.wrap(JobObject);
	let mut child = command.spawn()?;

	let stdout = child
		.stdout()
		.take()
		.expect("launcher stdout must be piped");
	let mut lines = BufReader::new(stdout).lines();
	let mut transcript = String::new();
	let mut marker = None;
	while let Some(line) = lines.next_line().await? {
		if line.starts_with(DESCENDANT_MARKER) {
			marker = Some(line);
			break;
		}
		if transcript.len() < 4096 {
			transcript.push_str(&line);
			transcript.push('\n');
		}
	}
	assert!(
		marker.is_some(),
		"launcher did not report descendant pid; stdout: {transcript:?}"
	);

	let started = Instant::now();
	sleep(Duration::from_millis(100)).await;
	assert_eq!(
		child.try_wait()?,
		None,
		"launcher exit must not report whole-Job completion while a descendant remains"
	);

	let status = child.wait().await?;
	assert!(status.success(), "launcher status: {status}");
	assert!(
		started.elapsed() >= Duration::from_millis(1000),
		"whole-Job wait returned before the descendant lifetime elapsed: {:?}",
		started.elapsed()
	);
	Ok(())
}
