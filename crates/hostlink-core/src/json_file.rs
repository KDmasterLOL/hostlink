//! Typed JSON file persistence built on runtime-neutral private file I/O.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io;
use std::path::Path;

/// Read and deserialize one complete JSON file with a caller-owned byte ceiling.
///
/// The file is rejected before full buffering when its known length exceeds `max_bytes`, and the
/// same limit remains enforced while reading so concurrent growth cannot bypass the ceiling.
pub fn read_json_file_bounded<T: DeserializeOwned>(path: &Path, max_bytes: usize) -> io::Result<T> {
    let bytes = crate::read_file_bounded(path, max_bytes)?;
    deserialize_json(&bytes)
}

fn deserialize_json<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Serialize pretty JSON into a newly created private file.
///
/// The destination must not already exist.
pub fn write_new_json_file<T: Serialize + ?Sized>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    crate::write_new_private_bytes(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::fs;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Fixture {
        name: String,
        value: u32,
    }

    #[test]
    fn json_file_round_trips_and_refuses_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let expected = Fixture {
            name: "Пример".to_owned(),
            value: 42,
        };

        write_new_json_file(&path, &expected).expect("write JSON");
        let actual: Fixture = read_json_file_bounded(&path, 1024).expect("read JSON");
        assert_eq!(actual, expected);
        assert_eq!(
            write_new_json_file(&path, &expected)
                .expect_err("existing JSON must be rejected")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn regression_inv_108_bounded_json_accepts_exact_limit_and_rejects_one_over() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let bytes = br#"{"name":"x","value":1}"#;
        fs::write(&path, bytes).expect("fixture");

        let actual: Fixture = read_json_file_bounded(&path, bytes.len()).expect("exact limit");
        assert_eq!(actual.name, "x");
        assert_eq!(actual.value, 1);
        assert_eq!(
            read_json_file_bounded::<Fixture>(&path, bytes.len() - 1)
                .expect_err("one byte over limit")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn regression_inv_108_bounded_json_preserves_invalid_data_classification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broken.json");
        fs::write(&path, b"{").expect("fixture");

        assert_eq!(
            read_json_file_bounded::<Fixture>(&path, 16)
                .expect_err("malformed JSON")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
