use std::io::Result;

#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;
use tokio::process::Command;

use super::{ChildWrapper, CommandWrap, CommandWrapper};

/// Wrapper which enables native Tokio kill-on-drop and also terminates the wrapped lifecycle.
///
/// Register this after process-tree wrappers such as `ProcessGroup` or `JobObject` when drop
/// should target the fully composed tree. Keeping Tokio's native kill-on-drop enabled also protects
/// failures that happen after spawn but before the wrapper chain is returned.
#[derive(Clone, Copy, Debug)]
pub struct KillOnDrop;

#[derive(Debug)]
struct KillOnDropChild {
	inner: Option<Box<dyn ChildWrapper>>,
}

impl KillOnDropChild {
	fn inner_ref(&self) -> &dyn ChildWrapper {
		self.inner
			.as_deref()
			.expect("kill-on-drop child is only empty while being consumed")
	}

	fn inner_mut_ref(&mut self) -> &mut dyn ChildWrapper {
		self.inner
			.as_deref_mut()
			.expect("kill-on-drop child is only empty while being consumed")
	}
}

impl CommandWrapper for KillOnDrop {
	fn pre_spawn(&mut self, command: &mut Command, _core: &CommandWrap) -> Result<()> {
		command.kill_on_drop(true);
		Ok(())
	}

	fn wrap_child(
		&mut self,
		inner: Box<dyn ChildWrapper>,
		_core: &CommandWrap,
	) -> Result<Box<dyn ChildWrapper>> {
		Ok(Box::new(KillOnDropChild { inner: Some(inner) }))
	}
}

impl ChildWrapper for KillOnDropChild {
	fn inner(&self) -> &dyn ChildWrapper {
		self.inner_ref()
	}

	fn inner_mut(&mut self) -> &mut dyn ChildWrapper {
		self.inner_mut_ref()
	}

	fn into_inner(mut self: Box<Self>) -> Box<dyn ChildWrapper> {
		self.inner
			.take()
			.expect("kill-on-drop child is only consumed once")
	}

	#[cfg(windows)]
	fn process_handle(&self) -> Option<BorrowedHandle<'_>> {
		self.inner_ref().process_handle()
	}
}

impl Drop for KillOnDropChild {
	fn drop(&mut self) {
		if let Some(inner) = self.inner.as_deref_mut() {
			let _ = inner.start_kill();
		}
	}
}
