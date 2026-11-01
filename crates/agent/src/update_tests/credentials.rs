//! Disposable private files only; no real HOME credential is read or changed.
use crate::agent_files::read_github_token;
use private_fs::PrivateDir;
use secrecy::ExposeSecret;
#[cfg(not(windows))]
use std::path::Path;
use std::{fs, io::Write};

fn credential(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDir::ensure(temp.path().join("credentials")).unwrap();
    dir.create("github-token")
        .unwrap()
        .write_all(bytes)
        .unwrap();
    let path = temp.path().join("credentials/github-token");
    (temp, path)
}

#[cfg(not(windows))]
#[test]
fn credential_location_uses_only_absolute_xdg_or_home() {
    use crate::agent_files::github_credential_path_from_config as resolve;
    let home = Some(Path::new("/disposable/home"));
    let expected = Path::new("/disposable/home/.config/hostlink/credentials/github-token");
    for xdg in [
        None,
        Some(Path::new("")),
        Some(Path::new("relative/config")),
    ] {
        assert_eq!(resolve(xdg, home).unwrap(), expected);
    }
    assert_eq!(
        resolve(Some(Path::new("/disposable/config")), home).unwrap(),
        Path::new("/disposable/config/hostlink/credentials/github-token")
    );
    assert!(resolve(None, None).is_err());
    assert!(resolve(None, Some(Path::new("relative/home"))).is_err());
    assert!(resolve(Some(Path::new("relative/config")), None).is_err());
    assert!(resolve(Some(Path::new("/disposable/config")), None).is_ok());
}

#[test]
fn private_credential_strips_only_one_trailing_line_ending() {
    for bytes in [
        b"fixture-credential".as_slice(),
        b"fixture-credential\n",
        b"fixture-credential\r\n",
    ] {
        let (_temp, path) = credential(bytes);
        let token = read_github_token(&path).unwrap();
        assert!(token.expose_secret() == "fixture-credential");
        assert!(fs::read(path).unwrap() == bytes);
    }
}

#[test]
fn invalid_credential_bytes_fail_without_echoing_contents() {
    for bytes in [
        b"".as_slice(),
        b"\n",
        b"\r\n",
        b" \n",
        b"fixture-credential\n\n",
        b"fixture-credential\r",
        b"fixture-credential\t",
        b"fixture-credential\0",
        b"fixture-credential\x7f",
        b"fixture-credential\x1b",
        b"fixture\ncredential",
        b" fixture-credential",
        b"fixture-credential ",
        b"fixture-credential\xff",
        "fixture-credential\u{85}".as_bytes(),
    ] {
        let (_temp, path) = credential(bytes);
        let error = read_github_token(&path).unwrap_err().to_string();
        assert!(!error.contains("fixture-credential"));
        assert!(error.contains("GitHub credential missing or unsafe"));
    }
}

#[test]
fn credential_read_is_bounded_and_missing_file_is_not_created() {
    let (_temp, path) = credential(&vec![b'a'; 8192]);
    assert!(read_github_token(&path).unwrap().expose_secret().len() == 8192);
    fs::write(&path, vec![b'a'; 8193]).unwrap();
    assert!(read_github_token(&path).is_err());
    fs::write(&path, vec![b'a'; 1024 * 1024]).unwrap();
    assert!(read_github_token(&path).is_err());
    fs::remove_file(&path).unwrap();
    assert!(read_github_token(&path).is_err());
    assert!(!path.exists());
    fs::create_dir(&path).unwrap();
    assert!(read_github_token(&path).is_err());
}

#[cfg(unix)]
#[test]
fn credential_mode_must_be_exactly_0600_and_is_never_repaired() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, path) = credential(b"fixture-credential");
    for mode in [0o400, 0o640, 0o644, 0o666, 0o700, 0o4600] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(read_github_token(&path).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            mode
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_github_token(&path).is_ok());
}

#[cfg(unix)]
#[test]
fn credential_links_and_aliased_ancestors_are_rejected() {
    let (temp, path) = credential(b"fixture-credential");
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(path.parent().unwrap(), &alias).unwrap();
    assert!(read_github_token(&alias.join("github-token")).is_err());
    fs::remove_file(alias).unwrap();
    let original = path.with_file_name("original");
    fs::rename(&path, &original).unwrap();
    std::os::unix::fs::symlink(&original, &path).unwrap();
    assert!(read_github_token(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&original, &path).unwrap();
    assert!(read_github_token(&path).is_err());
    fs::remove_file(original).unwrap();
    assert!(read_github_token(&path).is_ok());
}
