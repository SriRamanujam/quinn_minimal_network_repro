use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;

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

        let config = quinn::ClientConfig {
            transport: Arc::new(quinn::TransportConfig::default()),
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
    async fn open_new_connection(&mut self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        Ok(self.conn.open_bi().await?)
    }

    /// Make the request to the remote peer and receive a response.
    /// TODO: timeouts
    pub async fn make_request(&mut self, msg: &str) -> anyhow::Result<()> {
        let (mut send, mut recv) = self.open_new_connection().await?;

        // send the request...
        send.write_all(msg.as_bytes()).await?;
        send.finish().await?;

        // ...and return the response.
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

        let frozen = incoming.freeze();
        let ret = std::str::from_utf8(frozen.as_ref())?;
        println!(
            "Received response {} bytes long from server: {}",
            msg_size, ret
        );

        Ok(())
    }

    pub fn close(&self) {
        self.endpoint.close(0u8.into(), b"done");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut client = QuicClient::new_insecure("127.0.0.1:5000").await?;

    for i in 1..1000000000 {
        client
            .make_request("Hello, world!")
            .await
            .context(format!("Could not make request number {}", i))?;

        std::thread::sleep(std::time::Duration::new(1, 0)); // sleep for 1 second between requests
    }

    client.close();

    Ok(())
}

pub const CUSTOM_PROTO: &[&[u8]] = &[b"cstm-01"];
