//! The TLS configuration FTPS and S3 share.
//!
//! Both reach a server over TLS and both offer the same one checkbox, so the
//! answer to "what does this client trust" is written once. What differs is
//! only what the configuration is then handed to: suppaftp wraps it in a
//! connector of its own, reqwest takes it as it is.
//!
//! rustls on `ring` throughout, for the reason named in `Cargo.toml`: the
//! default backend's `aws-lc-sys` wants cmake and NASM to build on Windows.

use std::sync::{Arc, Mutex};

use ring::digest;
use rust_i18n::t;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// Builds the configuration for one connection.
///
/// Two of them, and the difference between them is the whole point of the
/// checkbox in the form: the ordinary one trusts what the operating system
/// trusts, and the other trusts anything. FTPS has a third, [`pinned`], for a
/// certificate the user has looked at and accepted.
pub fn config(accept_invalid_cert: bool) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| t!("tls.setup_failed", error = e).into_owned())?;

    if accept_invalid_cert {
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
            .with_no_client_auth());
    }
    Ok(builder
        .with_root_certificates(system_roots()?)
        .with_no_client_auth())
}

/// The operating system's own roots rather than a list compiled in here: a
/// company CA is installed in the system store and nowhere else, and a server
/// certificate signed by it must simply work.
fn system_roots() -> Result<RootCertStore, String> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for certificate in native.certs {
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        return Err(t!("tls.no_roots").into_owned());
    }
    Ok(roots)
}

/// The SHA-256 of a certificate as it came over the wire — what is pinned,
/// and what `openssl x509 -fingerprint -sha256` prints for the same file.
pub type Fingerprint = [u8; 32];

pub fn fingerprint_of(certificate: &[u8]) -> Fingerprint {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, certificate).as_ref());
    out
}

/// `AB:CD:…`, the way `openssl` writes a fingerprint, so the two can be held
/// side by side.
pub fn fingerprint_text(fingerprint: &Fingerprint) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A certificate the system's roots would not vouch for and no pin covered.
#[derive(Clone, Debug, PartialEq)]
pub struct Refused {
    pub fingerprint: Fingerprint,
    /// Why the roots said no, in words — "self-signed" is what most of these
    /// turn out to be, and the dialog should say so.
    pub reason: String,
}

/// What [`pinned`] lets through beyond the roots, and where it leaves the
/// certificate it turned down.
///
/// The handshake cannot stop and ask: verification is synchronous and runs
/// deep inside it. So the certificate is put aside here, the connection fails
/// as it would have anyway, and whoever opened it asks the question and tries
/// again once the answer is a yes.
#[derive(Clone, Default)]
pub struct Pinning {
    pub pins: Vec<Fingerprint>,
    refused: Arc<Mutex<Option<Refused>>>,
}

impl Pinning {
    pub fn new(pins: Vec<Fingerprint>) -> Self {
        Self {
            pins,
            refused: Arc::default(),
        }
    }

    /// The certificate the last handshake turned down, if one did.
    pub fn take_refused(&self) -> Option<Refused> {
        self.refused.lock().ok()?.take()
    }
}

/// The ordinary check first, then the pins.
///
/// A certificate the roots vouch for never reaches the pins, so nothing about
/// a properly issued one changes. One they do not vouch for is accepted only
/// if exactly it — not a key, not a name — was accepted before; anything else
/// fails with the roots' own reason and is left in [`Pinning`] to be asked
/// about.
pub fn pinned(pinning: &Pinning) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = WebPkiServerVerifier::builder_with_provider(
        Arc::new(system_roots()?),
        Arc::clone(&provider),
    )
    .build()
    .map_err(|e| t!("tls.setup_failed", error = e).into_owned())?;

    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| t!("tls.setup_failed", error = e).into_owned())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RootsThenPins {
            roots,
            pinning: pinning.clone(),
        }))
        .with_no_client_auth())
}

/// What a refusal by the roots means, for someone deciding whether to trust
/// the certificate anyway.
fn reason(error: &TlsError) -> String {
    match error {
        TlsError::InvalidCertificate(CertificateError::UnknownIssuer) => {
            t!("tls.reason_unknown_issuer").into_owned()
        }
        TlsError::InvalidCertificate(CertificateError::NotValidForName)
        | TlsError::InvalidCertificate(CertificateError::NotValidForNameContext { .. }) => {
            t!("tls.reason_wrong_name").into_owned()
        }
        TlsError::InvalidCertificate(CertificateError::Expired)
        | TlsError::InvalidCertificate(CertificateError::ExpiredContext { .. }) => {
            t!("tls.reason_expired").into_owned()
        }
        TlsError::InvalidCertificate(CertificateError::NotValidYet)
        | TlsError::InvalidCertificate(CertificateError::NotValidYetContext { .. }) => {
            t!("tls.reason_not_yet_valid").into_owned()
        }
        other => other.to_string(),
    }
}

#[derive(Debug)]
struct RootsThenPins {
    roots: Arc<WebPkiServerVerifier>,
    pinning: Pinning,
}

impl std::fmt::Debug for Pinning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pinning")
            .field("pins", &self.pins.len())
            .finish()
    }
}

impl ServerCertVerifier for RootsThenPins {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let error = match self.roots.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => return Ok(verified),
            Err(error) => error,
        };

        let fingerprint = fingerprint_of(end_entity.as_ref());
        if self.pinning.pins.contains(&fingerprint) {
            return Ok(ServerCertVerified::assertion());
        }
        // Only what the roots refused on the certificate's own merits is
        // worth asking about. A malformed one or a broken chain of a
        // different kind is not a decision for the user.
        if matches!(error, TlsError::InvalidCertificate(_)) {
            if let Ok(mut slot) = self.pinning.refused.lock() {
                *slot = Some(Refused {
                    fingerprint,
                    reason: reason(&error),
                });
            }
        }
        Err(error)
    }

    // The signatures are checked as for any other connection: they are what
    // ties the handshake to the key in the certificate that was pinned.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.roots.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.roots.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.roots.supported_verify_schemes()
    }
}

/// Accepts every server certificate, for "Don't verify certificate".
///
/// What this gives up is the half of TLS that tells the intended server from
/// anyone able to answer in its place; what is left is encryption against
/// someone merely listening. That is a real difference and a deliberate one —
/// it is the only way to reach a server with a self-signed certificate — but
/// it is not the same as a checked connection, and the form says so.
///
/// The signature checks below are *not* waived: they are what ties the
/// handshake to the key in the certificate that was presented. Skipping those
/// as well would leave a connection anyone could sit in the middle of without
/// even holding a key.
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier(pinning: &Pinning) -> RootsThenPins {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        RootsThenPins {
            roots: WebPkiServerVerifier::builder_with_provider(
                Arc::new(system_roots().expect("roots")),
                provider,
            )
            .build()
            .expect("verifier"),
            pinning: pinning.clone(),
        }
    }

    fn check(pinning: &Pinning, certificate: &[u8]) -> Result<ServerCertVerified, TlsError> {
        verifier(pinning).verify_server_cert(
            &CertificateDer::from(certificate.to_vec()),
            &[],
            &ServerName::try_from("ftp.example.test").expect("name"),
            &[],
            UnixTime::now(),
        )
    }

    #[test]
    fn a_fingerprint_is_written_the_way_openssl_writes_it() {
        let mut fingerprint = [0u8; 32];
        fingerprint[0] = 0xab;
        fingerprint[31] = 0x01;
        let text = fingerprint_text(&fingerprint);
        assert!(text.starts_with("AB:00:"), "{text}");
        assert!(text.ends_with(":01"), "{text}");
        assert_eq!(text.len(), 32 * 3 - 1);
    }

    /// The roots refuse anything they cannot place — here bytes that are no
    /// certificate at all. What happens after that is the pins' business.
    #[test]
    fn what_the_roots_refuse_is_kept_to_ask_about_unless_it_is_pinned() {
        let certificate = b"not a real certificate";

        let unpinned = Pinning::default();
        assert!(check(&unpinned, certificate).is_err());
        let refused = unpinned.take_refused().expect("kept to ask about");
        assert_eq!(refused.fingerprint, fingerprint_of(certificate));
        // Taken means gone: a second look finds nothing.
        assert!(unpinned.take_refused().is_none());

        let pinned = Pinning::new(vec![fingerprint_of(certificate)]);
        assert!(check(&pinned, certificate).is_ok());
        assert!(pinned.take_refused().is_none());

        let other = Pinning::new(vec![[7u8; 32]]);
        assert!(check(&other, certificate).is_err());
        assert!(other.take_refused().is_some());
    }

    #[test]
    fn a_refusal_is_explained_in_words() {
        assert!(reason(&TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
        .contains("self-signed"));
        assert_eq!(
            reason(&TlsError::InvalidCertificate(CertificateError::Expired)),
            "expired"
        );
        assert_eq!(
            reason(&TlsError::InvalidCertificate(
                CertificateError::NotValidForName
            )),
            "issued for a different name"
        );
    }
}
