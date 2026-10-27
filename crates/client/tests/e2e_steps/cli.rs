use std::{path::Path, process::Command};

use super::cli_env;

pub(super) fn verify_cli_exec(client_bin: &Path, cli_config: &Path) {
    let mut exec = Command::new(client_bin);
    cli_env(&mut exec, cli_config);
    let result = exec
        .args([
            "exec",
            "--host",
            "managed-fixture",
            "--command",
            "printf managed-ok; printf managed-error >&2; exit 7",
        ])
        .output()
        .expect("run name-selected nested SSH exec");
    assert_eq!(result.status.code(), Some(7));
    assert_eq!(result.stdout, b"managed-ok");
    assert_eq!(result.stderr, b"managed-error");
}
