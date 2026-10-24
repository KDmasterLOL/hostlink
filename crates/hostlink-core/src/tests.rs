use super::*;
use serde::Serialize;
use std::io::{self, BufReader};

#[derive(Serialize)]
struct Record<'a> {
    value: &'a str,
}

#[test]
fn json_line_round_trips_and_emits_one_newline() {
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &Record { value: "first" }).expect("write JSON line");

    assert_eq!(bytes, b"{\"value\":\"first\"}\n");
    let decoded: serde_json::Value =
        read_json_line_bounded(BufReader::new(bytes.as_slice()), bytes.len()).expect("read line");
    assert_eq!(decoded["value"], "first");
}

#[test]
fn bounded_reader_accepts_exact_limit_and_rejects_overflow() {
    let exact = b"{}\n";
    assert_eq!(
        read_json_line_bounded::<serde_json::Value>(BufReader::new(exact.as_slice()), exact.len())
            .expect("exact bound"),
        serde_json::json!({})
    );

    let error = read_json_line_bounded::<serde_json::Value>(
        BufReader::new(exact.as_slice()),
        exact.len() - 1,
    )
    .expect_err("over bound");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn bounded_reader_preserves_eof_and_json_error_kinds() {
    let eof = read_json_line_bounded::<serde_json::Value>(BufReader::new([].as_slice()), 8)
        .expect_err("empty input");
    assert_eq!(eof.kind(), io::ErrorKind::UnexpectedEof);

    let invalid =
        read_json_line_bounded::<serde_json::Value>(BufReader::new(b"not-json\n".as_slice()), 32)
            .expect_err("invalid JSON");
    assert_eq!(invalid.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn constant_time_string_comparison_keeps_exact_byte_semantics() {
    assert!(constant_time_str_eq("same-secret", "same-secret"));
    assert!(!constant_time_str_eq("same-secret", "same-secreu"));
    assert!(!constant_time_str_eq("same-secret", "same-secret-longer"));
    assert!(constant_time_eq(b"token", b"token"));
    assert!(!constant_time_eq(b"token", b"toke"));
}
