use crate::cli::{args::HostTarget, commands::hosts::connect_target};
use crossterm::terminal;
use hostlink::connect::HostConnection;
use std::{
    error::Error,
    io::{self, IsTerminal},
    path::Path,
};

const MAX_TERMINAL_NAME_BYTES: usize = 64;
const MAX_TERMINAL_DIMENSION: u16 = 32_767;

pub(super) async fn interactive(
    host: Option<&str>,
    config: Option<&Path>,
) -> Result<i32, Box<dyn Error>> {
    ensure_terminal(io::stdin().is_terminal(), io::stdout().is_terminal())?;
    let terminal_name = terminal_name(std::env::var("TERM").ok().as_deref());
    let (columns, rows) = terminal::size()?;
    let columns = clip_dimension(columns);
    let rows = clip_dimension(rows);

    let connection = match host {
        Some(host) => {
            connect_target(&HostTarget {
                config: config.map(Path::to_path_buf),
                host: Some(host.to_owned()),
            })
            .await?
        }
        None => {
            let path = config.ok_or("--config is required when HOST is omitted")?;
            HostConnection::connect(&crate::cli::load_host_spec(path)?).await?
        }
    };

    // A drop guard restores cooked mode on ordinary errors and unwinding panics.
    let mut raw_mode = match RawModeGuard::enable() {
        Ok(guard) => guard,
        Err(error) => {
            return match connection.close().await {
                Ok(()) => Err(error.into()),
                Err(cleanup) => Err(io::Error::other(format!(
                    "could not enable local raw mode: {error}; SSH session cleanup failed: {cleanup}"
                ))
                .into()),
            };
        }
    };
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let session_result = connection
        .interactive(&terminal_name, columns, rows, &mut stdin, &mut stdout)
        .await;
    let restore_result = raw_mode.restore();
    let close_result = connection.close().await;
    match (session_result, restore_result, close_result) {
        (Ok(code), Ok(()), Ok(())) => Ok(i32::try_from(code).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SSH exit status exceeds process exit range",
            )
        })?),
        (Err(error), Ok(()), Ok(())) => Err(Box::new(error)),
        (Ok(_), Err(error), Ok(())) => Err(Box::new(error)),
        (Ok(_), Ok(()), Err(error)) => Err(Box::new(error)),
        (session, terminal, cleanup) => Err(io::Error::other(format!(
            "interactive SSH cleanup incomplete (session: {}; terminal restore: {}; SSH close: {})",
            session
                .err()
                .map_or_else(|| "ok".to_owned(), |error| error.to_string()),
            terminal
                .err()
                .map_or_else(|| "ok".to_owned(), |error| error.to_string()),
            cleanup
                .err()
                .map_or_else(|| "ok".to_owned(), |error| error.to_string()),
        ))
        .into()),
    }
}

fn ensure_terminal(stdin_is_terminal: bool, stdout_is_terminal: bool) -> io::Result<()> {
    if !stdin_is_terminal || !stdout_is_terminal {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hostlink ssh requires local terminal stdin and stdout",
        ));
    }
    Ok(())
}

fn terminal_name(value: Option<&str>) -> String {
    match value {
        Some(value)
            if !value.is_empty()
                && value.len() <= MAX_TERMINAL_NAME_BYTES
                && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) =>
        {
            value.to_owned()
        }
        _ => "xterm".to_owned(),
    }
}

fn clip_dimension(value: u16) -> u16 {
    value.clamp(1, MAX_TERMINAL_DIMENSION)
}

struct RawModeGuard(bool);

impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self(true))
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.0 {
            let result = terminal::disable_raw_mode();
            self.0 = result.is_err();
            result
        } else {
            Ok(())
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.0 {
            let _ = terminal::disable_raw_mode();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_terminal_input_and_output() {
        assert!(ensure_terminal(true, true).is_ok());
        assert!(ensure_terminal(false, true).is_err());
        assert!(ensure_terminal(true, false).is_err());
    }

    #[test]
    fn terminal_type_is_bounded_printable_ascii_or_xterm() {
        assert_eq!(terminal_name(Some("xterm-256color")), "xterm-256color");
        assert_eq!(terminal_name(Some("")), "xterm");
        assert_eq!(terminal_name(Some("bad\nterm")), "xterm");
        assert_eq!(terminal_name(Some(&"t".repeat(65))), "xterm");
    }

    #[test]
    fn dimensions_are_clipped_to_ssh_pty_limit() {
        assert_eq!(clip_dimension(0), 1);
        assert_eq!(clip_dimension(80), 80);
        assert_eq!(clip_dimension(u16::MAX), MAX_TERMINAL_DIMENSION);
    }

    #[test]
    fn cli_accepts_positional_host_or_direct_config_selector() {
        use crate::cli::args::{Cli, Command};
        use clap::Parser;

        assert!(matches!(
            Cli::try_parse_from(["hostlink", "ssh", "home-linux"]).unwrap().command,
            Command::Ssh {
                host: Some(host),
                config: None
            } if host == "home-linux"
        ));
        assert!(Cli::try_parse_from(["hostlink", "ssh"]).is_err());
        assert!(Cli::try_parse_from(["hostlink", "ssh", "home-linux", "other"]).is_err());
        assert!(matches!(
            Cli::try_parse_from(["hostlink", "ssh", "--config", "host.json"])
                .unwrap()
                .command,
            Command::Ssh {
                host: None,
                config: Some(_)
            }
        ));
        assert!(
            Cli::try_parse_from(["hostlink", "ssh", "home-linux", "--config", "x.json"]).is_err()
        );
        assert!(Cli::try_parse_from(["hostlink", "check", "--host", "home-linux"]).is_ok());
    }
}
