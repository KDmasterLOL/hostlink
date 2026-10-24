use super::*;
use onec_agent_protocol::SecretEnvironment;

pub(super) fn validate_environment_name(name: &str) -> AppResult<()> {
    if name.is_empty() || name.contains(['=', '\0']) {
        return Err(crate::invalid_config(format!(
            "invalid environment variable name {name:?}"
        )));
    }
    Ok(())
}

pub(super) fn resolve_secret_env(
    values: &[String],
    ordinary_env: &BTreeMap<String, String>,
) -> AppResult<SecretEnvironment> {
    let mut bindings = Vec::<(String, String)>::with_capacity(values.len());

    for binding in values {
        let (name, source_env) = binding.split_once('=').ok_or_else(|| {
            crate::invalid_config(format!(
                "--secret-env expects KEY=SOURCE_ENV, got {binding:?}"
            ))
        })?;
        validate_environment_name(name)?;
        validate_environment_name(source_env)?;

        if ordinary_env
            .keys()
            .any(|ordinary| environment_names_collide(ordinary, name))
        {
            return Err(crate::invalid_config(format!(
                "environment variable {name:?} cannot be supplied by both --env and --secret-env"
            )));
        }
        if bindings
            .iter()
            .any(|(existing, _)| environment_names_collide(existing, name))
        {
            return Err(crate::invalid_config(format!(
                "--secret-env repeats variable {name:?}"
            )));
        }

        bindings.push((name.to_owned(), source_env.to_owned()));
    }

    let mut secrets = BTreeMap::new();
    for (name, source_env) in bindings {
        let value = std::env::var(&source_env).map_err(|error| match error {
            std::env::VarError::NotPresent => crate::invalid_config(format!(
                "secret source environment variable {source_env:?} is not set"
            )),
            std::env::VarError::NotUnicode(_) => crate::invalid_config(format!(
                "secret source environment variable {source_env:?} is not valid UTF-8"
            )),
        })?;
        if value.is_empty() {
            return Err(crate::invalid_config(format!(
                "secret source environment variable {source_env:?} is empty"
            )));
        }
        secrets.insert(name, value);
    }
    Ok(SecretEnvironment::new(secrets))
}

fn environment_names_collide(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn secret_env_bindings_fail_closed_on_shape_duplicates_and_ordinary_env_collisions() {
        let env = BTreeMap::from([("PASSWORD".to_owned(), "ordinary".to_owned())]);

        for invalid in [
            vec!["NO_EQUALS".to_owned()],
            vec!["=SOURCE_ENV".to_owned()],
            vec!["BAD=NAME=SOURCE_ENV".to_owned()],
        ] {
            assert!(resolve_secret_env(&invalid, &BTreeMap::new()).is_err());
        }

        let duplicate = vec![
            "PASSWORD=FIRST_SECRET".to_owned(),
            "PASSWORD=SECOND_SECRET".to_owned(),
        ];
        let error =
            resolve_secret_env(&duplicate, &BTreeMap::new()).expect_err("duplicate secret target");
        assert!(error.to_string().contains("repeats variable"));

        let collision = resolve_secret_env(&["PASSWORD=FIRST_SECRET".to_owned()], &env)
            .expect_err("ordinary/secret collision");
        assert!(
            collision
                .to_string()
                .contains("both --env and --secret-env")
        );
    }

    #[test]
    fn resolved_secret_environment_debug_never_contains_plaintext() {
        let _guard = ENV_LOCK.lock().expect("environment lock");
        const ENV_NAME: &str = "ONEC_ACCESS_SECRET_SOURCE_TEST";
        let previous = env::var_os(ENV_NAME);
        unsafe { env::set_var(ENV_NAME, "hub-secret-sentinel") };

        let resolved = resolve_secret_env(
            &[format!("ONEC_TEST_PASSWORD={ENV_NAME}")],
            &BTreeMap::new(),
        )
        .expect("source environment resolution");
        let debug = format!("{resolved:?}");
        assert!(debug.contains("ONEC_TEST_PASSWORD"));
        assert!(!debug.contains("hub-secret-sentinel"));

        match previous {
            Some(value) => unsafe { env::set_var(ENV_NAME, value) },
            None => unsafe { env::remove_var(ENV_NAME) },
        }
    }

    #[test]
    fn missing_source_error_contains_reference_but_not_unrelated_process_secrets() {
        let _guard = ENV_LOCK.lock().expect("environment lock");
        const SENTINEL_ENV: &str = "ONEC_ACCESS_UNRELATED_SECRET_SENTINEL";
        let previous = env::var_os(SENTINEL_ENV);
        unsafe { env::set_var(SENTINEL_ENV, "must-never-appear") };

        let error = resolve_secret_env(
            &["PASSWORD=ONEC_ACCESS_MISSING_SECRET_SOURCE".to_owned()],
            &BTreeMap::new(),
        )
        .expect_err("missing source");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("ONEC_ACCESS_MISSING_SECRET_SOURCE"));
        assert!(!rendered.contains("must-never-appear"));

        match previous {
            Some(value) => unsafe { env::set_var(SENTINEL_ENV, value) },
            None => unsafe { env::remove_var(SENTINEL_ENV) },
        }
    }
}
