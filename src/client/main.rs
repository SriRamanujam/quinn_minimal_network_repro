use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use tokio::time::timeout;
use std::{convert::TryFrom, net::SocketAddr, time::Duration};
use std::sync::Arc;
use tracing_futures::Instrument;

mod insecure {
    use rustls;
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

#[derive(Clone)]
pub struct QuicClient {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl QuicClient {
    /// Creates a new QuicClient.
    pub async fn new(addr: &str) -> Result<QuicClient> {
        QuicClient::create(addr, false).await
    }

    /// Creates a new QuicClient that does not verify certificates. Used mainly for testing.
    pub async fn new_insecure(addr: &str) -> Result<QuicClient> {
        QuicClient::create(addr, true).await
    }

    #[doc(hidden)]
    async fn create(addr: &str, insecure: bool) -> Result<QuicClient> {
        let addr: SocketAddr = addr.parse()?;

        let mut crypto = rustls::ClientConfig::new();
        crypto.versions = vec![rustls::ProtocolVersion::TLSv1_3]; // we only want to support this version.
        if insecure {
            crypto
                .dangerous()
                .set_certificate_verifier(Arc::new(insecure::NoCertificateVerification {}));
        }

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.receive_window(u32::MAX.into());
        transport_config.send_window(u32::MAX.into());
        transport_config.stream_receive_window(1153433); // 110% of 1MiB.

        let config = quinn::ClientConfig {
            transport: Arc::new(transport_config),
            crypto: Arc::new(crypto),
        };

        let mut client_config = quinn::ClientConfigBuilder::new(config);

        client_config.protocols(CUSTOM_PROTO);

        let (endpoint, _) = quinn::Endpoint::builder()
            .bind(&"[::]:0".parse().unwrap())
            .context("Could not bind client endpoint")?;

        let conn = endpoint
            .connect_with(client_config.build(), &addr, "localhost")?
            .await
            .context(format!("Could not connect to {}", &addr))?;

        let quinn::NewConnection {
            connection: conn, ..
        } = { conn };

        Ok(QuicClient { endpoint, conn })
    }

    #[doc(hidden)]
    async fn open_new_connection(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        Ok(self.conn.open_bi().await?)
    }

    /// Make the request to the remote peer and receive a response.
    pub async fn make_request(&self, msg: usize) -> anyhow::Result<()> {
        let (mut send, mut recv) = self.open_new_connection().await?;

        async fn do_request(msg: usize, send: &mut quinn::SendStream, recv: &mut quinn::RecvStream) -> Result<()> {
            // send the request...
            info!("Sending request...");
            send.write_all(&msg.to_string().into_bytes()).await?;
            send.finish().await?;
            debug!("request sent!");

            // ...and return the response.
            info!("Reading response...");
            let mut incoming = bytes::BytesMut::new();
            let mut recv_buffer = Vec::<u8>::with_capacity(1048576); // 1 MiB receive buffer
            recv_buffer.resize_with(1048576, || 0x0);

            while let Some((data, offset)) = recv
                .read_unordered()
                .await
                .map_err(|e| anyhow!("could not read message from recv stream: {}", e))? 
            {
                debug!("Read {} bytes from stream at offset {}", data.len(), offset);
                let offset_as_usize = usize::try_from(offset)?;
                let max_extent = offset_as_usize + data.len();

                if max_extent > incoming.len() {
                    incoming.resize(max_extent, 0x0);
                }

                incoming[offset_as_usize..max_extent].copy_from_slice(&data[..]);
            }
            info!("Response fully read!");

            Ok(())
        }

        let x = do_request(msg, &mut send, &mut recv).instrument(tracing::info_span!("Making request and waiting for response"));

        let x = timeout(Duration::from_millis(10000), x);
        
        x.await.map_err(|e| {
            error!("Request timed out: {}", e);
            anyhow!("Request timed out: {}", e)
        })??;

        Ok(())
    }

    pub fn close(&self) {
        self.endpoint.close(0u8.into(), b"done");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default().with_ansi(false).init();

    // TUNABLES //
    let num_reqs = 512;
    let use_spawn = false;
    // END TUNABLES //

    let client = QuicClient::new_insecure("127.0.0.1:5000").await?;

    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Result<usize>>(num_reqs);

    info!("Starting {} spawned requests", num_reqs);

    for i in 0..num_reqs {
        let c = client.clone();
        let mut s = sender.clone();

        let f = async move {
            let x = c.make_request(i).await.map(|_| i);

            if let Err(e) = s.send(x).await {
                error!("Could not send message to receiver! {}", e);
            }
        }.instrument(tracing::info_span!("Request", num = i));

        if use_spawn {
            // spawn it off
            tokio::spawn(f);
        } else {
            f.await;
        }
    }

    info!("Started {} spawned requests, collecting responses", num_reqs);

    let mut completed_tasks = 0;
    let mut num_trials = 0;

    while let Some(s) = receiver.recv().await {
        match s {
            Ok(req) => { 
                info!("Completed task {}!", req);
                completed_tasks += 1;
            },
            Err(e) => debug!("Task returned error: {}", e)
        }

        num_trials += 1;

        if completed_tasks > num_reqs {
            warn!("completed_tasks > num_reqs: {} > {}", completed_tasks, num_reqs);
        }

        if completed_tasks == num_reqs {
            break;
        }
    }

    client.close();

    info!("Got successful results from {} spawned tasks with {} trials", num_reqs, num_trials);

    Ok(())
}

pub const CUSTOM_PROTO: &[&[u8]] = &[b"cstm-01"];
