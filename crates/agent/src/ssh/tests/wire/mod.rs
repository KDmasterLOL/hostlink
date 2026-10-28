//! Real encrypted/authenticated russh sessions over in-memory streams. This
//! supplements TCP interop; it does not exercise sockets or HostConnection.
use super::*;
use crate::jobs::JobId;
const JOB_FRAME_MAX_BYTES: usize = 64 * 1024;
use base64::Engine as _;
use futures::FutureExt as _;
use serde_json::{Value, json};
use std::panic::AssertUnwindSafe;

mod support;
use support::*;

#[tokio::test]
async fn actual_ssh_jobs_seal_start_output_owner_framing_and_cancel() {
    if std::env::var("HOSTLINK_REQUIRE_NATIVE_CONTAINMENT").as_deref() == Ok("1") {
        // Required native acceptance must fail on the actual weak backend even
        // when this host cannot initialize the private filesystem fixture.
        crate::jobs::process_tests::native_containment_available();
    }
    let mut fixture = WireFixture::new().await;
    let result = AssertUnwindSafe(tokio::time::timeout(
        Duration::from_secs(30),
        scenario(&mut fixture),
    ))
    .catch_unwind()
    .await;
    // Even a failed assertion cancels and drains the real worker/session tasks.
    tokio::time::timeout(Duration::from_secs(15), fixture.close())
        .await
        .expect("wire fixture cleanup deadline");
    match result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => panic!("bounded SSH wire scenario exceeded its deadline"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn scenario(fixture: &mut WireFixture) {
    use std::os::unix::fs::PermissionsExt;
    let first = fixture.connect(0).await;
    fixture.rejects_subsystem(first, "hostlink-jobs-v1").await;
    let owner = format!(
        "{:x}",
        Sha256::digest(fixture.keys[0].public_key().public_key_bytes())
    );
    let artifacts = fixture.jobs.store.artifacts(&owner).unwrap();
    let bytes = std::fs::read(std::fs::canonicalize("/bin/sh").unwrap()).unwrap();
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let name = format!("{sha256}.upload");
    let upload = artifacts.upload_root().join(&name);
    std::fs::write(&upload, &bytes).unwrap();
    std::fs::set_permissions(&upload, std::fs::Permissions::from_mode(0o600)).unwrap();
    let sealed = fixture
        .rpc(
            first,
            &json!({
                "op":"seal","name":name,"sha256":sha256,"size":bytes.len(),
            }),
            false,
        )
        .await;
    assert_eq!(sealed["ok"], true);
    assert_eq!(sealed["sha256"], sha256);
    assert_eq!(sealed.as_object().unwrap().len(), 3);
    let program = sealed["program"].as_str().unwrap();
    assert_eq!(
        std::fs::metadata(program).unwrap().permissions().mode() & 0o777,
        0o500
    );
    let id = JobId::new().to_string();
    let spec = json!({
        "program":program,"source_sha256":sha256,"cwd":fixture.root.path(),
        "args":["-c",r"printf x >> counter; printf '\000\377'; printf '\377E' >&2; exit 7"],
    });
    let start = json!({"op":"run","id":id,"spec":spec});
    let mut legacy = start.clone();
    legacy["version"] = json!(1);
    assert_eq!(fixture.rpc(first, &legacy, false).await["ok"], false);
    let listed = fixture
        .rpc(first, &json!({"op":"list","page":1}), false)
        .await;
    assert_eq!(listed["jobs"], json!([]));
    let source_outsider = fixture.connect(1).await;
    reject_unsafe_sources(fixture, first, source_outsider, &spec, &bytes).await;
    assert_eq!(
        fixture
            .rpc(first, &json!({"op":"status","id":id}), true)
            .await,
        json!({"ok":false,"error":"invalid jobs frame"})
    );
    if !crate::jobs::process_tests::native_containment_available() {
        reject_weak_containment(fixture, first, source_outsider, &id, &start).await;
        return;
    }

    let ack_not_consumed = fixture.send(first, &start, false).await;
    wait_file(&fixture.root.path().join("counter")).await;
    let listed = fixture
        .rpc(first, &json!({"op":"list","page":1}), false)
        .await;
    assert_eq!(listed["jobs"][0]["id"], id);
    assert_eq!(listed["jobs"].as_array().unwrap().len(), 1);

    fixture.disconnect(first).await;
    drop(ack_not_consumed);
    let resumed = fixture.connect(0).await;
    fixture
        .wait_state(resumed, &id, json!({"state":"exited","code":7}))
        .await;
    let expected = json!({
        "ok":true,"id":id,"state":{"state":"exited","code":7},
        "data_base64":null,"next_offset":null,"eof":null,
    });
    assert_eq!(fixture.rpc(resumed, &start, false).await, expected);
    assert_eq!(
        std::fs::read(fixture.root.path().join("counter")).unwrap(),
        b"x"
    );
    for (stream, raw) in [
        ("stdout", b"\0\xff".as_slice()),
        ("stderr", b"\xffE".as_slice()),
    ] {
        let output = fixture
            .rpc(
                resumed,
                &json!({
                    "op":"logs","id":id,"stream":stream,"offset":0,
                }),
                false,
            )
            .await;
        assert_eq!(
            output,
            json!({
                "ok":true,"id":id,"state":{"state":"exited","code":7},
                "data_base64":base64::engine::general_purpose::STANDARD.encode(raw),"next_offset":2,"eof":true,
            })
        );
    }
    let mut changed = start.clone();
    changed["spec"]["args"] = json!(["-c", "printf replayed >> counter"]);
    assert_eq!(
        fixture.rpc(resumed, &changed, false).await,
        json!({"ok":false,"error":"job admission failed"})
    );
    let outsider = fixture.connect(1).await;
    for request in [
        json!({"op":"status","id":id}),
        start,
        json!({"op":"cancel","id":id}),
        json!({"op":"logs","id":id,"stream":"stdout","offset":0}),
    ] {
        let error = match request["op"].as_str().unwrap() {
            "run" => "job admission failed",
            "logs" => "job output unavailable",
            _ => "job status unavailable",
        };
        let denied = fixture.rpc(outsider, &request, false).await;
        assert_eq!(denied, json!({"ok":false,"error":error}));
        if request["op"] != "run" {
            let mut absent = request;
            absent["id"] = json!(JobId::new().to_string());
            assert_eq!(
                fixture.rpc(outsider, &absent, false).await,
                denied,
                "foreign and missing jobs must not disclose identity, lifecycle or result"
            );
        }
    }
    assert_eq!(
        fixture
            .rpc(resumed, &json!({"op":"status","id":id}), true)
            .await,
        json!({"ok":false,"error":"invalid jobs frame"})
    );
    cancel_tree(fixture, resumed, outsider, spec).await;
}

async fn reject_unsafe_sources(
    fixture: &WireFixture,
    owner: usize,
    outsider: usize,
    spec: &Value,
    bytes: &[u8],
) {
    use std::os::unix::fs::PermissionsExt;
    let request = |source: &Path| {
        let mut spec = spec.clone();
        spec["program"] = json!(source);
        json!({"op":"run","id":JobId::new().to_string(),"spec":spec})
    };
    let program = Path::new(spec["program"].as_str().unwrap());
    assert_eq!(
        fixture.rpc(outsider, &request(program), false).await["ok"],
        false
    );
    let parent = fixture.root.path().join("writable-parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let raw = parent.join(program.file_name().unwrap());
    std::fs::write(&raw, bytes).unwrap();
    std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o500)).unwrap();
    let alias = fixture.root.path().join("sealed-alias");
    std::os::unix::fs::symlink(program, &alias).unwrap();
    for source in [&raw, &alias] {
        assert_eq!(
            fixture.rpc(owner, &request(source), false).await["ok"],
            false
        );
    }
    let sealed_parent = program.parent().unwrap();
    std::fs::set_permissions(sealed_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        fixture.rpc(owner, &request(program), false).await["ok"],
        false
    );
    std::fs::set_permissions(sealed_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fixture.rpc(owner, &request(program), false).await["ok"],
        false
    );
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    std::fs::write(program, &changed).unwrap();
    std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(
        fixture.rpc(owner, &request(program), false).await["ok"],
        false
    );
    std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(program, bytes).unwrap();
    std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(
        fixture
            .rpc(owner, &json!({"op":"list","page":1}), false)
            .await["jobs"],
        json!([]),
        "source authorization failures must never enqueue"
    );
}

async fn reject_weak_containment(
    fixture: &mut WireFixture,
    first: usize,
    outsider: usize,
    id: &str,
    start: &Value,
) {
    let ack_not_consumed = fixture.send(first, start, false).await;
    // Separate SSH channels can overtake admission. Observe the committed ID
    // through authenticated List without consuming the deliberately lost ACK.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let listed = fixture
                .rpc(first, &json!({"op":"list","page":1}), false)
                .await;
            assert_eq!(listed["ok"], true);
            if listed["jobs"]
                .as_array()
                .expect("authenticated job list")
                .iter()
                .any(|job| job["id"] == id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("lost-ACK run becomes visible in authenticated list");
    fixture
        .wait_state(first, id, json!({"state":"failed"}))
        .await;
    fixture.disconnect(first).await;
    drop(ack_not_consumed);
    let resumed = fixture.connect(0).await;
    assert_eq!(
        fixture.rpc(resumed, start, false).await,
        json!({"ok":true,"id":id,"state":{"state":"failed"},"data_base64":null,"next_offset":null,"eof":null})
    );
    assert!(
        !fixture.root.path().join("counter").exists(),
        "weak backend must not spawn or replay"
    );
    for stream in ["stdout", "stderr"] {
        let logs = json!({"op":"logs","id":id,"stream":stream,"offset":0});
        assert_eq!(
            fixture.rpc(resumed, &logs, false).await,
            json!({"ok":true,"id":id,"state":{"state":"failed"},"data_base64":"","next_offset":0,"eof":true})
        );
        assert_eq!(fixture.rpc(outsider, &logs, false).await["ok"], false);
    }
    for request in [
        start.clone(),
        json!({"op":"status","id":id}),
        json!({"op":"cancel","id":id}),
    ] {
        assert_eq!(fixture.rpc(outsider, &request, false).await["ok"], false);
    }
}

async fn cancel_tree(fixture: &WireFixture, owner: usize, outsider: usize, mut spec: Value) {
    let id = JobId::new().to_string();
    let pid_path = fixture.root.path().join("descendant-pid");
    spec["args"] = json!([
        "-c",
        format!("sleep 300 & echo $! > '{}'; wait", pid_path.display())
    ]);
    assert_eq!(
        fixture
            .rpc(owner, &json!({"op":"run","id":id,"spec":spec}), false)
            .await["ok"],
        true
    );
    wait_file(&pid_path).await;
    let pid: u32 = std::fs::read_to_string(&pid_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let cancel = json!({"op":"cancel","id":id});
    assert_eq!(
        fixture.rpc(outsider, &cancel, false).await,
        json!({"ok":false,"error":"job status unavailable"})
    );
    assert_eq!(fixture.rpc(owner, &cancel, false).await["ok"], true);
    fixture
        .wait_state(owner, &id, json!({"state":"failed"}))
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while crate::jobs::process_tests::linux_process_is_running(pid) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled descendant is confirmed dead before state acceptance");
    assert_eq!(
        fixture.rpc(owner, &cancel, false).await["state"],
        json!({"state":"failed"})
    );
}
