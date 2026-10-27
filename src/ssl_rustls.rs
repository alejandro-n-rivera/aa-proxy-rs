//! rustls-based TLS backend for aa-proxy-rs.
//!
//! Replaces the openssl SslMemBuf / SslStream / ssl_builder stack.
//! Handles V1 certificates (Google Automotive Link / Android Auto) via:
//!   - client side: ResolvesClientCert resolver bypasses rustls cert parsing
//!   - server side: custom ClientCertVerifier skips version check
//!
//! Usage in mitm.rs:
//!   use crate::ssl_rustls::{AaConnection, SslMemBuf};

use crate::mitm::ProxyType;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::sign::CertifiedKey;
use rustls::version::TLS12;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ---------------------------------------------------------------------------
// SslMemBuf — in-memory BIO equivalent
// ---------------------------------------------------------------------------

/// In-memory TLS transport for rustls, equivalent to OpenSSL BIO_s_mem.
///
/// `incoming`: caller writes peer data here → rustls reads it via read_tls()
/// `outgoing`: rustls writes generated data here → caller drains it via drain_outgoing()
pub struct SslMemBuf {
    incoming: Vec<u8>,
    incoming_pos: usize,
    outgoing: Vec<u8>,
}

impl SslMemBuf {
    pub fn new() -> Self {
        Self {
            incoming: Vec::new(),
            incoming_pos: 0,
            outgoing: Vec::new(),
        }
    }

    /// Feed data received from the peer (stripped from AA encapsulation).
    /// Equivalent to old `write_from`.
    pub fn feed_incoming(&mut self, data: &[u8]) {
        // compact already-consumed prefix first
        if self.incoming_pos > 0 {
            self.incoming.drain(..self.incoming_pos);
            self.incoming_pos = 0;
        }
        self.incoming.extend_from_slice(data);
    }

    /// Take all data rustls generated (to be wrapped in AA encapsulation).
    /// Equivalent to old `read_to`.
    pub fn drain_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }
}

/// rustls calls Read on SslMemBuf to consume incoming TLS bytes.
impl Read for SslMemBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = &self.incoming[self.incoming_pos..];
        if available.is_empty() {
            // No data — signal WouldBlock so rustls stops reading.
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.incoming_pos += n;
        Ok(n)
    }
}

/// rustls calls Write on SslMemBuf to emit outgoing TLS bytes.
impl Write for SslMemBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Custom certificate verifiers — accept V1 certs
// ---------------------------------------------------------------------------

fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

/// ServerCertVerifier that accepts any certificate, including V1.
/// Used on the HeadUnit path where we connect as a client toward the real HU.
#[derive(Debug)]
struct AaServerCertVerifier(Arc<CryptoProvider>);

impl AaServerCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(default_provider()))
    }
}

impl ServerCertVerifier for AaServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// ClientCertVerifier that accepts any client certificate, including V1.
/// Used on the MobileDevice path where we act as a TLS server toward the phone.
#[derive(Debug)]
struct AaClientCertVerifier(Arc<CryptoProvider>);

impl AaClientCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(default_provider()))
    }
}

impl ClientCertVerifier for AaClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// ResolvesServerCert that returns a pre-loaded CertifiedKey without letting
/// rustls parse and validate the certificate — V1 workaround for the server path.
/// with_single_cert() validates the cert version; with_cert_resolver() does not.
#[derive(Debug)]
struct AaServerCertResolver(Arc<CertifiedKey>);

impl AaServerCertResolver {
    fn new(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Result<Arc<Self>> {
        let signing_key = aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)?;
        Ok(Arc::new(Self(Arc::new(CertifiedKey::new(
            vec![cert],
            signing_key,
        )))))
    }
}

impl rustls::server::ResolvesServerCert for AaServerCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// rustls parse and validate the certificate.  This is the V1 workaround for
/// the client path: with_client_auth_cert() validates the cert version;
/// with_client_cert_resolver() does not.
#[derive(Debug)]
struct AaClientCertResolver(Arc<CertifiedKey>);

impl AaClientCertResolver {
    fn new(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Result<Arc<Self>> {
        let signing_key = aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)?;
        Ok(Arc::new(Self(Arc::new(CertifiedKey::new(
            vec![cert],
            signing_key,
        )))))
    }
}

impl rustls::client::ResolvesClientCert for AaClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// AaConnection — unified server/client connection wrapper
// ---------------------------------------------------------------------------

/// Wraps either a rustls ServerConnection or ClientConnection.
/// Provides process() / encrypt() / decrypt() in terms of SslMemBuf so callers
/// do not need to know which side they are on.
pub enum AaConnection {
    Server(rustls::ServerConnection),
    Client(rustls::ClientConnection),
}

impl AaConnection {
    /// Drive the TLS state machine one step:
    ///   1. feed any pending incoming bytes from mem_buf into rustls
    ///   2. process packets
    ///   3. flush any outgoing bytes rustls generated into mem_buf
    ///
    /// Returns whether the handshake is still in progress.
    pub fn process(&mut self, mem_buf: &mut SslMemBuf) -> std::result::Result<bool, rustls::Error> {
        match self {
            AaConnection::Server(c) => Self::process_conn(c, mem_buf),
            AaConnection::Client(c) => Self::process_conn(c, mem_buf),
        }
    }

    fn process_conn<Data>(
        conn: &mut rustls::ConnectionCommon<Data>,
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<bool, rustls::Error> {
        // Feed all available incoming bytes into rustls.
        loop {
            match conn.read_tls(mem_buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        conn.process_new_packets()?;
        // Flush all pending TLS records — may need multiple calls.
        while conn.wants_write() {
            let _ = conn.write_tls(&mut mem_buf.outgoing);
        }
        Ok(conn.is_handshaking())
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            AaConnection::Server(c) => c.is_handshaking(),
            AaConnection::Client(c) => c.is_handshaking(),
        }
    }

    /// Closest available equivalent to openssl's `SSL_state_string_long()`.
    ///
    /// rustls deliberately does NOT expose its internal handshake state
    /// machine (no "write client hello" / "write finished" granularity is
    /// available — those states are private implementation details). This
    /// reports the closest public approximation: protocol version, whether
    /// the handshake is a resumption, and whether it's still in progress.
    pub fn state_string(&self) -> String {
        let (version, kind, handshaking) = match self {
            AaConnection::Server(c) => {
                (c.protocol_version(), c.handshake_kind(), c.is_handshaking())
            }
            AaConnection::Client(c) => {
                (c.protocol_version(), c.handshake_kind(), c.is_handshaking())
            }
        };
        if handshaking {
            "TLS handshake in progress".to_string()
        } else {
            let version = version
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "unknown version".to_string());
            let resumed = matches!(kind, Some(rustls::HandshakeKind::Resumed));
            format!(
                "SSL negotiation finished successfully ({version}{})",
                if resumed { ", resumed" } else { "" }
            )
        }
    }

    /// Returns negotiated cipher suite name, e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".
    /// Only available after handshake is complete.
    pub fn cipher_suite(&self) -> &'static str {
        let suite = match self {
            AaConnection::Server(c) => c.negotiated_cipher_suite(),
            AaConnection::Client(c) => c.negotiated_cipher_suite(),
        };
        suite
            .map(|s| s.suite().as_str().unwrap_or("unknown"))
            .unwrap_or("unknown")
    }

    /// Encrypt `plaintext` and append the ciphertext to `mem_buf.outgoing`.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<(), rustls::Error> {
        match self {
            AaConnection::Server(c) => Self::encrypt_conn(c, plaintext, mem_buf),
            AaConnection::Client(c) => Self::encrypt_conn(c, plaintext, mem_buf),
        }
    }

    fn encrypt_conn<Data>(
        conn: &mut rustls::ConnectionCommon<Data>,
        plaintext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<(), rustls::Error> {
        conn.writer()
            .write_all(plaintext)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        // write_tls may need multiple calls to flush all TLS records from
        // the internal buffer — loop until nothing more to write.
        while conn.wants_write() {
            let _ = conn.write_tls(&mut mem_buf.outgoing);
        }
        Ok(())
    }

    /// Feed `ciphertext` into rustls and return the decrypted plaintext.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        mem_buf.feed_incoming(ciphertext);
        match self {
            AaConnection::Server(c) => Self::decrypt_conn(c, mem_buf),
            AaConnection::Client(c) => Self::decrypt_conn(c, mem_buf),
        }
    }

    fn decrypt_conn<Data>(
        conn: &mut rustls::ConnectionCommon<Data>,
        mem_buf: &mut SslMemBuf,
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        // Loop read_tls until no more data in mem_buf (WouldBlock).
        loop {
            match conn.read_tls(mem_buf) {
                Ok(0) | Err(_) => break, // WouldBlock or EOF
                Ok(_) => {}
            }
        }
        conn.process_new_packets()?;
        // Flush any TLS records generated in response (e.g. alerts, tickets).
        while conn.wants_write() {
            let _ = conn.write_tls(&mut mem_buf.outgoing);
        }
        let mut plaintext = Vec::new();
        match conn.reader().read_to_end(&mut plaintext) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(rustls::Error::General(e.to_string())),
        }
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Public builder
// ---------------------------------------------------------------------------

// Only immutable certificate/key configuration is cached. Every session gets
// a new TLS state machine and the original no-resumption policy is retained.
#[derive(Clone, Debug)]
enum PreparedConfig {
    Server(Arc<ServerConfig>),
    Client(Arc<ClientConfig>),
}
struct CachedConfig {
    fingerprint: [u8; 32],
    config: PreparedConfig,
}
static SERVER_CONFIG: Mutex<Option<CachedConfig>> = Mutex::new(None);
static CLIENT_CONFIG: Mutex<Option<CachedConfig>> = Mutex::new(None);

fn prepared_config(proxy_type: ProxyType, keys_path: &str) -> Result<PreparedConfig> {
    let (prefix, slot) = match proxy_type {
        ProxyType::HeadUnit => ("md", &SERVER_CONFIG),
        ProxyType::MobileDevice => ("hu", &CLIENT_CONFIG),
    };
    // Read the actual inputs on every use: changed, deleted or invalid files
    // must not silently reuse the old key/config, regardless of timestamps.
    let cert_bytes = fs::read(format!("{keys_path}/{prefix}_cert.pem"))?;
    let key_bytes = fs::read(format!("{keys_path}/{prefix}_key.pem"))?;
    let mut hash = Sha256::new();
    hash.update((cert_bytes.len() as u64).to_le_bytes());
    hash.update(&cert_bytes);
    hash.update(&key_bytes);
    let fingerprint: [u8; 32] = hash.finalize().into();
    let mut cached = slot.lock().map_err(|_| "TLS preparation lock poisoned")?;
    if let Some(entry) = cached
        .as_ref()
        .filter(|entry| entry.fingerprint == fingerprint)
    {
        return Ok(entry.config.clone());
    }
    let started = Instant::now();
    let cert = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .next()
        .ok_or("no certificate in file")?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)?;
    let provider = default_provider();
    let config = match proxy_type {
        ProxyType::HeadUnit => {
            let resolver = AaServerCertResolver::new(cert, key)?;
            let mut config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&TLS12])?
                .with_client_cert_verifier(AaClientCertVerifier::new())
                .with_cert_resolver(resolver);
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            PreparedConfig::Server(Arc::new(config))
        }
        ProxyType::MobileDevice => {
            let resolver = AaClientCertResolver::new(cert, key)?;
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&TLS12])?
                .dangerous()
                .with_custom_certificate_verifier(AaServerCertVerifier::new())
                .with_client_cert_resolver(resolver);
            config.resumption = rustls::client::Resumption::disabled();
            PreparedConfig::Client(Arc::new(config))
        }
    };
    *cached = Some(CachedConfig {
        fingerprint,
        config: config.clone(),
    });
    log::info!(
        "TLS prepare: rustls {} configuration ready in {}ms",
        prefix,
        started.elapsed().as_millis()
    );
    Ok(config)
}

fn connection_from_prepared(config: PreparedConfig) -> Result<(AaConnection, SslMemBuf)> {
    let conn = match config {
        PreparedConfig::Server(config) => {
            AaConnection::Server(rustls::ServerConnection::new(config)?)
        }
        PreparedConfig::Client(config) => AaConnection::Client(rustls::ClientConnection::new(
            config,
            "android.auto".try_into()?,
        )?),
    };
    Ok((conn, SslMemBuf::new()))
}

pub fn ssl_builder(proxy_type: ProxyType, keys_path: &str) -> Result<(AaConnection, SslMemBuf)> {
    connection_from_prepared(prepared_config(proxy_type, keys_path)?)
}

// Heavy key parsing/validation never blocks the Tokio I/O worker, including
// when a fast phone wins the race with background preparation.
pub async fn ssl_builder_async(
    proxy_type: ProxyType,
    keys_path: &str,
) -> Result<(AaConnection, SslMemBuf)> {
    let path = keys_path.to_owned();
    tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let result = ssl_builder(proxy_type, &path);
        log::info!(
            "TLS setup: {:?} fresh connection built in {}ms on blocking worker",
            proxy_type,
            started.elapsed().as_millis()
        );
        result
    })
    .await?
}

pub fn prewarm_during_wifi_wait(keys_path: &str) {
    let path = keys_path.to_owned();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            // AWS-LC lazily initializes its process-wide entropy source on the
            // first random request. Key parsing alone does not exercise it.
            // Preserve that entropy source and overlap its one-time cost with
            // the phone's Wi-Fi association, never reuse random/TLS state.
            let started = Instant::now();
            let mut random = [0u8; 32];
            default_provider()
                .secure_random
                .fill(&mut random)
                .map_err(|_| "TLS entropy initialization failed")?;
            log::info!(
                "TLS prepare: entropy ready in {}ms during phone Wi-Fi wait",
                started.elapsed().as_millis()
            );
            prepared_config(ProxyType::HeadUnit, &path)?;
            prepared_config(ProxyType::MobileDevice, &path)?;
            Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => {
                log::info!("TLS prepare: both rustls configurations warmed during phone Wi-Fi wait")
            }
            Ok(Err(e)) => log::warn!(
                "TLS prepare: warmup failed; normal session setup will retry: {}",
                e
            ),
            Err(e) => log::warn!(
                "TLS prepare: warmup task failed; normal session setup will retry: {}",
                e
            ),
        }
    });
}

#[cfg(test)]
mod startup_tls_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn prepared_configs_are_reused_but_sessions_are_fresh_and_keys_revalidated() {
        let keys = std::env::var("AA_TEST_KEYS_PATH").expect("AA_TEST_KEYS_PATH required");
        let first = prepared_config(ProxyType::HeadUnit, &keys).unwrap();
        let second = prepared_config(ProxyType::HeadUnit, &keys).unwrap();
        match (&first, &second) {
            (PreparedConfig::Server(a), PreparedConfig::Server(b)) => assert!(Arc::ptr_eq(a, b)),
            _ => panic!("wrong role"),
        }
        // Two complete sessions must both perform full handshakes and transfer
        // application data; cached configuration must never share TLS state.
        let mut hellos = Vec::new();
        for _ in 0..2 {
            let (mut srv, mut sb) = ssl_builder(ProxyType::HeadUnit, &keys).unwrap();
            let (mut cli, mut cb) = ssl_builder(ProxyType::MobileDevice, &keys).unwrap();
            assert!(srv.is_handshaking() && cli.is_handshaking());
            cli.process(&mut cb).unwrap();
            let hello = cb.drain_outgoing();
            assert!(!hello.is_empty());
            hellos.push(hello.clone());
            sb.feed_incoming(&hello);
            for _ in 0..32 {
                srv.process(&mut sb).unwrap();
                cb.feed_incoming(&sb.drain_outgoing());
                cli.process(&mut cb).unwrap();
                sb.feed_incoming(&cb.drain_outgoing());
                if !srv.is_handshaking() && !cli.is_handshaking() {
                    break;
                }
            }
            assert!(!srv.is_handshaking() && !cli.is_handshaking());
            let payload = b"phone-to-head-unit";
            cli.encrypt(payload, &mut cb).unwrap();
            assert_eq!(srv.decrypt(&cb.drain_outgoing(), &mut sb).unwrap(), payload);
            let reply = b"head-unit-to-phone";
            srv.encrypt(reply, &mut sb).unwrap();
            assert_eq!(cli.decrypt(&sb.drain_outgoing(), &mut cb).unwrap(), reply);
        }
        assert_ne!(
            hellos[0], hellos[1],
            "TLS sessions must have fresh client randomness"
        );

        let tmp: PathBuf =
            std::env::temp_dir().join(format!("aa-tls-cache-test-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        for name in ["md_cert.pem", "md_key.pem"] {
            fs::copy(std::path::Path::new(&keys).join(name), tmp.join(name)).unwrap();
        }
        prepared_config(ProxyType::HeadUnit, tmp.to_str().unwrap()).unwrap();
        fs::write(tmp.join("md_key.pem"), b"invalid key").unwrap();
        assert!(
            prepared_config(ProxyType::HeadUnit, tmp.to_str().unwrap()).is_err(),
            "changed invalid key must not use cached config"
        );
        fs::remove_file(tmp.join("md_key.pem")).unwrap();
        assert!(
            prepared_config(ProxyType::HeadUnit, tmp.to_str().unwrap()).is_err(),
            "missing key must not use cached config"
        );
        fs::remove_dir_all(tmp).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preparation_and_async_fallback_return_fresh_connections() {
        let keys = std::env::var("AA_TEST_KEYS_PATH").expect("AA_TEST_KEYS_PATH required");
        prewarm_during_wifi_wait(&keys);
        let (server, _) = ssl_builder_async(ProxyType::HeadUnit, &keys).await.unwrap();
        let (client, _) = ssl_builder_async(ProxyType::MobileDevice, &keys)
            .await
            .unwrap();
        assert!(server.is_handshaking() && client.is_handshaking());
    }
}
