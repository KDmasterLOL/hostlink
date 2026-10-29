//! Exact task definition; XML parsing is delegated to roxmltree, scheduling to Windows.
#[cfg(windows)]
use super::*;
#[cfg(not(windows))]
use std::io;
#[cfg(not(windows))]
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[path = "task_xml_tests.rs"]
mod tests;

#[cfg(windows)]
pub(super) fn render(root: &Path) -> io::Result<String> {
    let sid = escape(&current_sid()?)?;
    let name = escape(&task_name(root)?)?;
    let executable = escape(
        agent_executable(root)
            .to_str()
            .ok_or_else(|| invalid("Agent path is not Unicode"))?,
    )?;
    let arguments = escape(&format!(
        "run --config={}",
        windows_quote(
            root.join("state/agent.json")
                .to_str()
                .ok_or_else(|| invalid("Agent config path is not Unicode"))?
        )
    ))?;
    let digest = sha256_file(&agent_executable(root))?;
    Ok(format!(
        r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Author>{sid}</Author><Description>HostLink Agent v2 sha256:{digest}</Description><URI>\{name}</URI></RegistrationInfo>
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
<Principals><Principal id="Agent"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
<Actions Context="Agent"><Exec><Command>{executable}</Command><Arguments>{arguments}</Arguments></Exec></Actions>
</Task>"#
    ))
}

fn escape(value: &str) -> io::Result<String> {
    if value
        .chars()
        .any(|c| c < ' ' || c == '\u{fffe}' || c == '\u{ffff}')
    {
        return Err(invalid(
            "task XML input contains unsupported control characters",
        ));
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

/// Compare all elements, namespaces, attributes and values after Windows has
/// normalized both definitions. Whitespace between elements is insignificant.
pub(super) fn equal(left: &str, right: &str) -> io::Result<bool> {
    let parse = |xml| roxmltree::Document::parse(xml).map_err(io::Error::other);
    let left = parse(left)?;
    let right = parse(right)?;
    Ok(equal_node(left.root_element(), right.root_element()))
}
fn equal_node(left: roxmltree::Node<'_, '_>, right: roxmltree::Node<'_, '_>) -> bool {
    if left.tag_name() != right.tag_name()
        || left.attributes().len() != right.attributes().len()
        || left.attributes().any(|a| {
            right
                .attributes()
                .find(|b| b.name() == a.name() && b.namespace() == a.namespace())
                .map(|b| b.value())
                != Some(a.value())
        })
    {
        return false;
    }
    let elements =
        |node: roxmltree::Node<'_, '_>| node.children().filter(|n| n.is_element()).count();
    if elements(left) != elements(right) {
        return false;
    }
    if elements(left) == 0 {
        return left.text().unwrap_or("") == right.text().unwrap_or("");
    }
    left.children()
        .filter(|n| n.is_element())
        .zip(right.children().filter(|n| n.is_element()))
        .all(|(a, b)| equal_node(a, b))
}
