use super::prelude::*;

#[cfg(all(feature = "kill-on-drop", feature = "process-group"))]
#[tokio::test]
async fn process_group_kill_on_drop_terminates_descendants() -> Result<()> {
	let mut child = CommandWrap::with_new("tests/multiproc_helper.rs", |command| {
		command
			.arg("1")
			.arg("30")
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
	})
	.wrap(ProcessGroup::leader())
	.wrap(KillOnDrop)
	.spawn()?;

	let stdout = child
		.stdout()
		.take()
		.expect("Option.unwrap(): get leader stdout");
	let mut lines = BufReader::new(stdout).lines();
	let Some(line) = lines.next_line().await? else {
		panic!("expected line with child pid");
	};
	let Some((parent, descendant)) = line.split_once(':') else {
		panic!("expected line with parent and child pids");
	};
	let parent = parent.parse::<i32>().unwrap();
	let descendant = descendant.parse::<i32>().unwrap();

	assert!(pid_alive(parent), "launcher should be alive before drop");
	assert!(
		pid_alive(descendant),
		"descendant should be alive before drop"
	);
	drop(child);

	for _ in 0..20 {
		if !pid_alive(parent) && !pid_alive(descendant) {
			break;
		}
		sleep(DIE_TIME).await;
	}
	assert!(!pid_alive(parent), "launcher survived kill-on-drop");
	assert!(!pid_alive(descendant), "descendant survived kill-on-drop");
	Ok(())
}
