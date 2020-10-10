use anyhow::{anyhow, Result};
use futures::{StreamExt, TryFutureExt};
use tracing_futures::Instrument;
use std::sync::Arc;
use quinn::ServerConfig;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use log::{debug, info};
use log::error;

pub const CUSTOM_PROTO: &[&[u8]] = &[b"cstm-01"];

fn main() {
    let exit_code = if let Err(e) = run() {
        error!("ERROR: {}", e);
        1
    } else {
        0
    };

    std::process::exit(exit_code);
}

#[tokio::main]
async fn run() -> Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default().with_ansi(false).init();

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.stream_window_uni(0);
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    transport_config.receive_window(u32::MAX.into());
    transport_config.send_window(u32::MAX.into());
    transport_config.stream_window_bidi(10240);
    transport_config.stream_receive_window(1153433); // 110% of 1MiB.
    let mut quinn_config = quinn::ServerConfig::default();
    quinn_config.transport = Arc::new(transport_config);

    let mut server_config_builder = quinn::ServerConfigBuilder::new(quinn_config);
    server_config_builder.enable_keylog();
    server_config_builder.use_stateless_retry(true);
    server_config_builder.protocols(CUSTOM_PROTO); // custom protocol

    let key_path = std::path::PathBuf::from("self_signed.key");

    let key = std::fs::read(&key_path)
        .map_err(|e| anyhow!("Could not read cert key file from self_signed.key: {}", e))?;
    let key = quinn::PrivateKey::from_pem(&key)
        .map_err(|e| anyhow!("Could not create PEM from private key: {}", e))?;

    let cert_path = std::path::PathBuf::from("self_signed.pem");
    let cert_chain = std::fs::read(&cert_path)
        .map_err(|e| anyhow!("Could not read certificate chain file: {}", e))?;
    let cert_chain = quinn::CertificateChain::from_pem(&cert_chain)
        .map_err(|e| anyhow!("Could not create certificate chain: {}", e))?;

    server_config_builder.certificate(cert_chain, key)?;

    let server_config = server_config_builder.build();

    tokio::try_join!(build_and_run_server(5000, server_config.clone()))?;

    info!("shutting down...");

    Ok(())
}

async fn build_and_run_server(port: u16, server_config: ServerConfig) -> Result<()> {
    let mut endpoint_builder = quinn::Endpoint::builder();
    endpoint_builder.listen(server_config.clone());

    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    let mut incoming = {
        let (endpoint, incoming) = endpoint_builder.bind(&socket_addr)?;
        info!("Server listening on {}", endpoint.local_addr()?);
        incoming
    };

    while let Some(conn) = incoming.next().await {
        info!("{}: new connection!", socket_addr);
        tokio::spawn(handle_conn(conn).unwrap_or_else(move |e| {
            info!("{}: connection failed: {}", socket_addr, e);
        }));
    }

    Ok(())
}

async fn handle_conn(conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        connection: _connection,
        mut bi_streams,
        ..
    } = conn.await?;

    // dispatch the actual handling as another future. concurrency!
    async {
        // each stream needs to be processed independently
        while let Some(stream) = bi_streams.next().await {
            let send_recv = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    // application closed, finish up early
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            tokio::spawn(
                handle_response(send_recv)
                    .unwrap_or_else(move |e| error!("Response failed: {}", e)),
            );
        }
        Ok(())
    }
    .await?;

    Ok(())
}

async fn handle_response(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    info!("received new message");

    let mut incoming = bytes::BytesMut::new();
    let mut recv_buffer = [0 as u8; 1024]; // 1 KiB socket recv buffer
    let mut msg_size = 0;

    while let Some(s) = recv
        .read(&mut recv_buffer)
        .await
        .map_err(|e| anyhow!("Could not read message from recv stream: {}", e))?
    {
        msg_size += s;
        incoming.extend_from_slice(&recv_buffer[0..s]);
    }

    let msg: usize = match String::from_utf8(incoming.to_vec()) {
        Ok(s) => s.parse().unwrap(),
        Err(e) => anyhow::bail!("Could not turn incoming message into string! {}", e)
    };

    let x: anyhow::Result<()> = async {
        info!("Received {} bytes from stream: {}", msg_size, msg);

        debug!("Performing read...");
        let body = tokio::task::spawn_blocking(|| -> Result<Vec<u8>> {
            Ok(std::fs::read("./random_data.bin")?)
        }).await??;

        info!("Read complete! Writing message to send stream...");
        send.write_all(&body).await?;

        debug!("closing send stream...");
        send.finish().await?;

        info!("response handled!");

        Ok(())
    }.instrument(tracing::info_span!("Response", num = msg)).await;

    x?;

    Ok(())
}
