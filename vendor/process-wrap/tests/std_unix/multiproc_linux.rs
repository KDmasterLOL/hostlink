#![cfg(target_os = "linux")]

use super::prelude::*;

#[cfg(feature = "process-group")]
#[test]
fn process_group_kill_leader() -> Result<()> {
	let mut leader = CommandWrap::with_new("tests/multiproc_helper.rs", |command| {
		command
			.arg("1")
			.arg("10")
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
	})
	.wrap(ProcessGroup::leader())
	.spawn()?;
	assert!(leader.try_wait()?.is_none(), "leader: pre kill");

	sleep(DIE_TIME);

	let stdout = leader
		.stdout()
		.take()
		.expect("Option.unwrap(): get leader stdout");
	let mut lines = BufReader::new(stdout).lines();
	let Some(Ok(line)) = lines.next() else {
		panic!("expected line with child pid");
	};
	let Some((parent, child)) = line.split_once(':') else {
		panic!("expected line with parent and child pids");
	};

	let parent = parent.parse::<i32>().unwrap();
	let child = child.parse::<i32>().unwrap();

	assert_eq!(parent, leader.id() as _);
	assert!(pid_alive(parent), "parent process should be alive");
	assert!(pid_alive(child), "child process should be alive");

	leader.kill().unwrap();
	sleep(DIE_TIME);
	assert!(!pid_alive(parent), "parent process should be dead");
	assert!(!pid_alive(child), "child process should be dead");

	Ok(())
}

#[cfg(feature = "process-group")]
#[test]
fn process_group_try_wait_keeps_waiting_for_orphaned_descendant() -> Result<()> {
	let mut leader = CommandWrap::with_new("tests/multiproc_helper.rs", |command| {
		command
			.arg("1")
			.arg("10")
			.arg("exit-after-spawn")
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
	})
	.wrap(ProcessGroup::leader())
	.spawn()?;

	let stdout = leader
		.stdout()
		.take()
		.expect("Option.unwrap(): get leader stdout");
	let mut lines = BufReader::new(stdout).lines();
	let Some(Ok(line)) = lines.next() else {
		panic!("expected line with child pid");
	};
	let Some((parent, child)) = line.split_once(':') else {
		panic!("expected line with parent and child pids");
	};
	let parent = parent.parse::<i32>().unwrap();
	let child = child.parse::<i32>().unwrap();

	assert_eq!(parent, leader.id() as _);
	sleep(Duration::from_millis(250));
	assert!(
		pid_alive(child),
		"orphaned descendant should still be alive"
	);
	let observed = leader.try_wait()?;

	nix::sys::signal::killpg(nix::unistd::Pid::from_raw(parent), Signal::SIGKILL).ok();
	for _ in 0..20 {
		if !pid_alive(child) {
			break;
		}
		sleep(DIE_TIME);
	}
	assert!(
		!pid_alive(child),
		"descendant should be gone after group kill"
	);
	assert_eq!(
		observed, None,
		"whole-group try_wait must not report completion while an orphaned descendant remains"
	);
	Ok(())
}

#[cfg(feature = "process-group")]
#[test]
fn process_group_wait_keeps_waiting_for_orphaned_descendant() -> Result<()> {
	let mut leader = CommandWrap::with_new("sh", |command| {
		command
			.args(["-c", "sleep 1 & exit 0"])
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null());
	})
	.wrap(ProcessGroup::leader())
	.spawn()?;

	let started = std::time::Instant::now();
	let status = leader.wait()?;
	assert!(status.success(), "launcher exit status: {status}");
	assert!(
		started.elapsed() >= Duration::from_millis(700),
		"whole-group wait returned before the descendant lifetime elapsed: {:?}",
		started.elapsed()
	);
	Ok(())
}

#[cfg(feature = "process-group")]
#[test]
fn process_group_kill_group() -> Result<()> {
	let mut leader = CommandWrap::with_new("tests/multiproc_helper.rs", |command| {
		command
			.arg("1")
			.arg("10")
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
	})
	.wrap(ProcessGroup::leader())
	.spawn()?;
	assert!(leader.try_wait()?.is_none(), "leader: pre kill");

	sleep(DIE_TIME);

	let stdout = leader
		.stdout()
		.take()
		.expect("Option.unwrap(): get leader stdout");
	let mut lines = BufReader::new(stdout).lines();
	let Some(Ok(line)) = lines.next() else {
		panic!("expected line with child pid");
	};
	let Some((parent, child)) = line.split_once(':') else {
		panic!("expected line with parent and child pids");
	};

	let parent = parent.parse::<i32>().unwrap();
	let child = child.parse::<i32>().unwrap();

	assert_eq!(parent, leader.id() as _);
	assert!(pid_alive(parent), "parent process should be alive");
	assert!(pid_alive(child), "child process should be alive");

	nix::sys::signal::killpg(nix::unistd::Pid::from_raw(parent), Signal::SIGKILL).unwrap();
	sleep(DIE_TIME);
	assert!(!pid_alive(child), "child process should be dead");
	leader.wait().unwrap();
	assert!(!pid_alive(parent), "parent process should be dead");

	Ok(())
}

#[cfg(feature = "process-session")]
#[test]
fn process_session_kill_leader() -> Result<()> {
	let mut leader = CommandWrap::with_new("tests/multiproc_helper.rs", |command| {
		command
			.arg("1")
			.arg("10")
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
	})
	.wrap(ProcessSession)
	.spawn()?;
	assert!(leader.try_wait()?.is_none(), "leader: pre kill");

	sleep(DIE_TIME);

	let stdout = leader
		.stdout()
		.take()
		.expect("Option.unwrap(): get leader stdout");
	let mut lines = BufReader::new(stdout).lines();
	let Some(Ok(line)) = lines.next() else {
		panic!("expected line with child pid");
	};
	let Some((parent, child)) = line.split_once(':') else {
		panic!("expected line with parent and child pids");
	};

	let parent = parent.parse::<i32>().unwrap();
	let child = child.parse::<i32>().unwrap();

	assert_eq!(parent, leader.id() as _);
	assert!(pid_alive(parent), "parent process should be alive");
	assert!(pid_alive(child), "child process should be alive");

	leader.kill().unwrap();
	sleep(DIE_TIME);
	assert!(!pid_alive(parent), "parent process should be dead");
	assert!(!pid_alive(child), "child process should be dead");

	Ok(())
}

#[cfg(feature = "process-session")]
#[test]
fn process_session_kill_group() -> Result<()> {
	let mut leader = CommandWrap::with_new("tests/multiproc_helper.rs", |command| {
		command
			.arg("1")
			.arg("10")
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
	})
	.wrap(ProcessSession)
	.spawn()?;
	assert!(leader.try_wait()?.is_none(), "leader: pre kill");

	sleep(DIE_TIME);

	let stdout = leader
		.stdout()
		.take()
		.expect("Option.unwrap(): get leader stdout");
	let mut lines = BufReader::new(stdout).lines();
	let Some(Ok(line)) = lines.next() else {
		panic!("expected line with child pid");
	};
	let Some((parent, child)) = line.split_once(':') else {
		panic!("expected line with parent and child pids");
	};

	let parent = parent.parse::<i32>().unwrap();
	let child = child.parse::<i32>().unwrap();

	assert_eq!(parent, leader.id() as _);
	assert!(pid_alive(parent), "parent process should be alive");
	assert!(pid_alive(child), "child process should be alive");

	nix::sys::signal::killpg(nix::unistd::Pid::from_raw(parent), Signal::SIGKILL).unwrap();
	sleep(DIE_TIME);
	assert!(!pid_alive(child), "child process should be dead");
	leader.wait().unwrap();
	assert!(!pid_alive(parent), "parent process should be dead");

	Ok(())
}
