use super::*;

pub(super) async fn stop_fixture_and_check_ssh_baseline(
    children: &mut Children,
    old_ssh_pids: &[u8],
    old_ssh_port: &[u8],
) {
    assert!(
        children.stop_all(),
        "all temporary fixture process groups must terminate"
    );
    let cleanup_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let current_pids = Command::new("pgrep")
            .args(["-x", "sshd"])
            .output()
            .expect("inspect sshd processes after fixture")
            .stdout;
        let current_port = Command::new("ss")
            .args(["-ltn", "sport", "=", ":22"])
            .output()
            .expect("inspect port 22 after fixture")
            .stdout;
        if current_pids == old_ssh_pids && current_port == old_ssh_port {
            break;
        }
        assert!(
            Instant::now() < cleanup_deadline,
            "temporary child processes must exit, pre-existing sshd PIDs and port 22 must stay unchanged"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
