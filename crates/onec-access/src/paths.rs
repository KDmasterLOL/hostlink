//! Controller-local onec-access paths.

use crate::AppResult;
use directories::ProjectDirs;
use std::{env, path::PathBuf};

pub(crate) fn config_path() -> AppResult<PathBuf> {
    let project_dirs = ProjectDirs::from("", "", "onec-access");
    config_path_from_sources(
        env::var_os("ONEC_ACCESS_CONFIG").map(PathBuf::from),
        project_dirs.as_ref(),
    )
}

fn config_path_from_sources(
    override_path: Option<PathBuf>,
    project_dirs: Option<&ProjectDirs>,
) -> AppResult<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    let root = project_dirs.map(ProjectDirs::config_dir).ok_or_else(|| {
        crate::invalid_config(
            "cannot determine OS-native application directories for onec-access".to_owned(),
        )
    })?;
    Ok(root.join("controller.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_config_uses_access_project_directory() {
        let dirs = ProjectDirs::from("", "", "onec-access").expect("test project dirs");
        assert_eq!(
            config_path_from_sources(None, Some(&dirs)).expect("config path"),
            dirs.config_dir().join("controller.json")
        );
        assert_eq!(dirs.project_path(), PathBuf::from("onec-access"));
    }

    #[test]
    fn controller_config_override_bypasses_missing_project_dirs() {
        let override_path = PathBuf::from("explicit-controller.json");
        assert_eq!(
            config_path_from_sources(Some(override_path.clone()), None).expect("override path"),
            override_path
        );
    }

    #[test]
    fn missing_project_dirs_returns_typed_error() {
        let error = config_path_from_sources(None, None).expect_err("missing dirs must fail");
        assert!(
            error
                .to_string()
                .contains("OS-native application directories")
        );
    }
}
