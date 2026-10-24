//! Operator-managed display labels, separate from canonical host selectors.

use super::*;

pub(crate) async fn set(target: String, label: Option<String>, clear: bool) -> AppResult<()> {
    let hub = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error("hostlink controller is not configured".to_owned())
    })?;
    let agent = hub
        .resolve_agent(&target)
        .await?
        .ok_or_else(|| crate::not_found_error(format!("hub-managed host {target:?}")))?;
    let receipt = hub
        .set_display_name(&agent, if clear { None } else { label.as_deref() })
        .await?;
    let observed = hub
        .list_agents()
        .await?
        .into_iter()
        .find(|record| record.machine_id == agent.machine_id)
        .ok_or_else(|| {
            crate::invalid_config("managed host disappeared after label update".to_owned())
        })?;
    if observed.name != agent.name || observed.display_name != receipt {
        return Err(crate::invalid_config(
            "hub display name readback does not match the committed value; reconcile before retry"
                .to_owned(),
        ));
    }
    println!(
        "Managed host {} display name: {}",
        observed.name,
        observed.display_name.as_deref().unwrap_or("(none)")
    );
    Ok(())
}
