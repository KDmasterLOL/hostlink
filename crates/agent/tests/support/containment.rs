/// Probe the actual backend without launching an OS process. Positive native
/// job tests retain their assertions, but cannot execute on a weak fallback.
pub fn supported() -> bool {
    let group = processkit::ProcessGroup::new().expect("create spawn-free containment probe");
    let mechanism = group.mechanism();
    let supported = match mechanism {
        processkit::Mechanism::CgroupV2 => cfg!(target_os = "linux"),
        processkit::Mechanism::JobObject => cfg!(windows),
        processkit::Mechanism::ProcessReaper => cfg!(target_os = "freebsd"),
        _ => false,
    };
    if !supported {
        let test = std::thread::current();
        let test = test.name().unwrap_or("unnamed test");
        assert!(
            std::env::var("HOSTLINK_REQUIRE_NATIVE_CONTAINMENT").as_deref() != Ok("1"),
            "HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1 [{test}]: required strong native containment is unavailable; actual backend={}",
            mechanism.name()
        );
        eprintln!(
            "NOT RUN [{test}]: positive native job execution requires strong containment; actual backend={}",
            mechanism.name()
        );
    }
    supported
}
