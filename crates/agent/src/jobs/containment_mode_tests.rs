//! Exercise the real native probe in child processes so environment changes
//! cannot race parallel tests or weaken production containment.

const CHILD_TEST: &str =
    "jobs::process_tests::containment_mode_tests::native_containment_probe_child";
const CHILD_ENV: &str = "HOSTLINK_CONTAINMENT_PROBE_CHILD";
const REQUIRE_ENV: &str = "HOSTLINK_REQUIRE_NATIVE_CONTAINMENT";

#[test]
#[ignore = "subprocess-only probe; invoked by parent regression"]
fn native_containment_probe_child() {
    if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
        let _ = super::native_containment_available();
    }
}

#[test]
fn native_containment_modes_use_real_capability_subprocess() {
    let group = processkit::ProcessGroup::new().expect("actual containment expectation");
    let supported = group.mechanism() == processkit::Mechanism::CgroupV2;
    for required in [false, true] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
            .env(CHILD_ENV, "1");
        if required {
            child.env(REQUIRE_ENV, "1");
        } else {
            child.env_remove(REQUIRE_ENV);
        }
        let output = child
            .output()
            .expect("run real containment probe subprocess");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("running 1 test"), "{stdout}\n{stderr}");
        assert_eq!(
            output.status.success(),
            supported || !required,
            "required={required}, actual backend={}: {stdout}\n{stderr}",
            group.mechanism().name()
        );
        if !supported {
            let diagnostic = if required {
                "HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1"
            } else {
                "NOT RUN ["
            };
            assert!(stderr.contains(diagnostic), "{stderr}");
            assert!(
                stderr.contains(CHILD_TEST),
                "skip/failure must name its test: {stderr}"
            );
            assert!(stderr.contains(group.mechanism().name()), "{stderr}");
            if required {
                assert!(
                    !stderr.contains("NOT RUN"),
                    "required mode cannot skip: {stderr}"
                );
            }
        }
    }
}
