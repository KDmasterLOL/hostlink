use super::*;
use serde_json::{Value, json};

fn metadata() -> Value {
    json!({"tag_name":"v1.2.3", "draft":false, "published_at":"2026-11-01", "assets":[
        {"name":"hostlink-agent-x86_64-unknown-linux-gnu", "url":format!("{RELEASES}/assets/1"), "state":"uploaded", "digest":format!("sha256:{}", "a".repeat(64))}
    ]})
}

#[test]
fn family_preflight_requires_every_exact_asset_from_one_release() {
    let mut value = metadata();
    for (index, target) in OsFamily::Windows.targets().iter().enumerate() {
        value["assets"].as_array_mut().unwrap().push(json!({
            "name": target.asset_name(), "url": format!("{RELEASES}/assets/{}", index + 2),
            "state": "uploaded", "digest": format!("sha256:{}", "b".repeat(64))
        }));
    }
    let resolve = |value: &Value| {
        let release = parse_release(&serde_json::to_vec(value).unwrap(), None).unwrap();
        selections_from_release(
            &release,
            OsFamily::Windows.targets(),
            "host".into(),
            "hostlink".into(),
            "https://hub.example".into(),
            None,
            None,
        )
    };
    let selections = resolve(&value).unwrap();
    assert_eq!(
        selections.iter().map(|s| s.target).collect::<Vec<_>>(),
        OsFamily::Windows.targets()
    );
    for index in 1..=3 {
        let mut missing = value.clone();
        missing["assets"].as_array_mut().unwrap().remove(index);
        assert!(resolve(&missing).is_err());
        let mut invalid = value.clone();
        invalid["assets"][index]["digest"] = Value::Null;
        assert!(resolve(&invalid).is_err());
    }
    assert_eq!(OsFamily::Linux.targets(), &[Target::LinuxX64]);
}

#[test]
fn release_requires_exact_published_version_unique_asset_and_digest() {
    assert_eq!(
        release_url(None).unwrap().as_str(),
        format!("{RELEASES}/latest")
    );
    assert_eq!(
        release_url(Some("1.2.3")).unwrap().as_str(),
        format!("{RELEASES}/tags/v1.2.3")
    );
    assert!(release_url(Some("latest")).is_err());
    let parse = |value: &Value| parse_release(&serde_json::to_vec(value).unwrap(), Some("1.2.3"));
    let release = parse(&metadata()).unwrap();
    assert_eq!(
        select_asset(&release, &Target::LinuxX64.asset_name())
            .unwrap()
            .1,
        "a".repeat(64)
    );
    for target in [Target::Win7X86, Target::Win7X64, Target::Win11X64] {
        assert!(select_asset(&release, &target.asset_name()).is_err());
    }
    // Older script/ZIP assets must never substitute for the selected raw binary.
    for old in [
        "Install-HostLink-Agent.ps1",
        "hostlink-agent-x86_64-unknown-linux-gnu.zip",
    ] {
        let mut value = metadata();
        value["assets"][0]["name"] = json!(old);
        assert!(select_asset(&parse(&value).unwrap(), &Target::LinuxX64.asset_name()).is_err());
    }
    for (key, bad) in [
        ("draft", json!(true)),
        ("published_at", Value::Null),
        ("tag_name", json!("v9.9.9")),
    ] {
        let mut value = metadata();
        value[key] = bad;
        assert!(parse(&value).is_err());
    }
    for (key, bad) in [
        ("digest", Value::Null),
        ("digest", json!("sha256:abc")),
        ("state", json!("new")),
    ] {
        let mut value = metadata();
        value["assets"][0][key] = bad;
        assert!(select_asset(&parse(&value).unwrap(), &Target::LinuxX64.asset_name()).is_err());
    }
    let mut value = metadata();
    let duplicate = value["assets"][0].clone();
    value["assets"].as_array_mut().unwrap().push(duplicate);
    assert!(select_asset(&parse(&value).unwrap(), &Target::LinuxX64.asset_name()).is_err());
}
