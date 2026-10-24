use std::io::Result;

#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;

use super::{ChildWrapper, CommandWrap, CommandWrapper};

/// Wrapper which terminates the wrapped child lifecycle when the child wrapper is dropped.
///
/// Register this after process-tree wrappers such as `ProcessGroup` or `JobObject` when drop
/// should target the fully composed tree. The wrapper remains useful on its own for an ordinary
/// child as well.
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
		let Some(inner) = self.inner.as_deref_mut() else {
			return;
		};

		if inner.start_kill().is_ok() {
			let _ = inner.wait();
		}
	}
}
