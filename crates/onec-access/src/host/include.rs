//! Idempotent ownership of the managed Include block in the user's SSH config.

use super::*;

pub(super) fn install_managed_include(user_config: &Path, generated: &Path) -> AppResult<()> {
    let generated_path = ssh_path(generated)?;
    if let Some(parent) = user_config.parent() {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    let existing_bytes = if user_config.exists() {
        onec_core::read_file_bounded(user_config, USER_SSH_CONFIG_MAX_BYTES)
            .map_err(|source| io_error(user_config, source))?
    } else {
        Vec::new()
    };
    let existing = std::str::from_utf8(&existing_bytes).map_err(|source| {
        io_error(
            user_config,
            std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        )
    })?;
    let cleaned = remove_legacy_onec_ops_include(&remove_managed_include_block(existing)?);
    let external_include = format!("Include {generated_path}");
    let has_external_include = cleaned
        .lines()
        .map(str::trim)
        .any(|line| line == external_include);

    if has_external_include {
        if cleaned != existing {
            write_atomic(user_config, cleaned.as_bytes())?;
        }
        return onec_core::restrict_private_file(user_config).map_err(crate::private_path_error);
    }

    let include = format!(
        "{MANAGED_INCLUDE_BEGIN}\nInclude {}\n{MANAGED_INCLUDE_END}\n",
        generated_path
    );
    let mut next = cleaned.trim_end_matches(['\r', '\n']).to_owned();
    if !next.is_empty() {
        next.push_str("\n\n");
    }
    next.push_str(&include);
    write_atomic(user_config, next.as_bytes())?;
    onec_core::restrict_private_file(user_config).map_err(crate::private_path_error)
}

fn remove_legacy_onec_ops_include(value: &str) -> String {
    const LEGACY_COMMENT: &str =
        "# onec-ops owns generated per-target aliases, while Chezmoi owns this include.";

    let lines = value.split_inclusive('\n').collect::<Vec<_>>();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.trim() == LEGACY_COMMENT
            && lines
                .get(index + 1)
                .is_some_and(|next| is_legacy_onec_ops_include(next))
        {
            index += 2;
            continue;
        }
        if is_legacy_onec_ops_include(line) {
            index += 1;
            continue;
        }
        output.push_str(line);
        index += 1;
    }
    output
}

fn is_legacy_onec_ops_include(line: &str) -> bool {
    let Some(path) = line.trim().strip_prefix("Include ") else {
        return false;
    };
    let path = path.trim().trim_matches('"').replace('\\', "/");
    path == "~/.config/onec-ops/ssh_config" || path.ends_with("/.config/onec-ops/ssh_config")
}

pub(super) fn remove_managed_include_block(value: &str) -> AppResult<String> {
    let Some(start) = value.find(MANAGED_INCLUDE_BEGIN) else {
        if value.contains(MANAGED_INCLUDE_END) {
            return Err(crate::invalid_config(
                "~/.ssh/config contains an unmatched managed SSH block end marker".to_owned(),
            ));
        }
        return Ok(value.to_owned());
    };
    let Some(relative_end) = value[start..].find(MANAGED_INCLUDE_END) else {
        return Err(crate::invalid_config(
            "~/.ssh/config contains an unmatched managed SSH block start marker".to_owned(),
        ));
    };
    let end_marker = start + relative_end + MANAGED_INCLUDE_END.len();
    let line_end = value[end_marker..]
        .find('\n')
        .map(|offset| end_marker + offset + 1)
        .unwrap_or(value.len());
    let mut output = String::with_capacity(value.len());
    output.push_str(&value[..start]);
    output.push_str(&value[line_end..]);
    if output.contains(MANAGED_INCLUDE_BEGIN) || output.contains(MANAGED_INCLUDE_END) {
        return Err(crate::invalid_config(
            "~/.ssh/config contains multiple managed SSH blocks; remove the duplicate manually"
                .to_owned(),
        ));
    }
    Ok(output)
}
