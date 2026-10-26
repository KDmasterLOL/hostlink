use std::fs::OpenOptions;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(|value| value.to_str()) {
        Some("exit7") => {
            let mut marker = OpenOptions::new()
                .create(true)
                .append(true)
                .open("launch-count")
                .expect("open fixture launch marker");
            marker.write_all(b"x").expect("write fixture launch marker");
            io::stdout()
                .write_all(&[0, 255])
                .expect("write exact binary stdout");
            io::stderr()
                .write_all(&[255, b'E'])
                .expect("write exact binary stderr");
            io::stdout().flush().expect("flush fixture stdout");
            io::stderr().flush().expect("flush fixture stderr");
            std::process::exit(7);
        }
        Some("tree") => {
            let pid_file = args.next().expect("descendant PID file argument");
            let child = Command::new(std::env::current_exe().expect("fixture executable path"))
                .arg("descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn descendant within Agent Job Object");
            std::fs::write(pid_file, child.id().to_string()).expect("write descendant PID");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        Some("descendant") => loop {
            thread::sleep(Duration::from_secs(1));
        },
        _ => panic!("fixture requires one supported mode"),
    }
}
