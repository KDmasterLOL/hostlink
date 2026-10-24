use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum TargetEffect {
    ReadOnly,
    RunOwned,
    Disposable,
}

impl From<TargetEffect> for hostlink_access::ManagedTargetEffect {
    fn from(value: TargetEffect) -> Self {
        match value {
            TargetEffect::ReadOnly => Self::ReadOnly,
            TargetEffect::RunOwned => Self::RunOwned,
            TargetEffect::Disposable => Self::Disposable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum NativeExecutionEffect {
    RunOwned,
    Disposable,
}

impl From<NativeExecutionEffect> for hostlink_protocol::NativeExecutionEffect {
    fn from(value: NativeExecutionEffect) -> Self {
        match value {
            NativeExecutionEffect::RunOwned => Self::RunOwned,
            NativeExecutionEffect::Disposable => Self::Disposable,
        }
    }
}

impl From<NativeExecutionEffect> for hostlink_access::ManagedTargetEffect {
    fn from(value: NativeExecutionEffect) -> Self {
        match value {
            NativeExecutionEffect::RunOwned => Self::RunOwned,
            NativeExecutionEffect::Disposable => Self::Disposable,
        }
    }
}
