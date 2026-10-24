//! TCP connect request handling.

use super::*;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

pub(super) fn handle(
    stream: TcpStream,
    request: AgentRequestKind,
    async_handle: &tokio::runtime::Handle,
) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    async_handle.block_on(handle_async(stream, request))
}

async fn handle_async(stream: TcpStream, request: AgentRequestKind) -> io::Result<()> {
    let mut stream = tokio::net::TcpStream::from_std(stream)?;
    match request {
        AgentRequestKind::TcpConnect {
            host,
            port,
            timeout_ms,
        } => {
            let target = match connect_target(&host, port, timeout_ms).await {
                Ok(target) => target,
                Err(error) => {
                    write_json_line_async(
                        &mut stream,
                        &AgentResponse::failure(format!(
                            "failed to connect to {host}:{port}: {error}"
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            };
            write_json_line_async(
                &mut stream,
                &AgentResponse::success(AgentResponseKind::TcpReady),
            )
            .await?;
            bridge_tcp(stream, target).await
        }
        _ => unreachable!("request routed to wrong control handler"),
    }
}

async fn write_json_line_async<T: Serialize + ?Sized>(
    stream: &mut tokio::net::TcpStream,
    value: &T,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await
}
