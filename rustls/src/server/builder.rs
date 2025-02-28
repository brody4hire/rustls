use alloc::vec::Vec;
use core::marker::PhantomData;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::{ResolvesServerCert, ServerConfig, handy};
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::error::Error;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::super_alias::{CfgRc, CfgRcRef, CfgRcX, CfgX, ErrorRc, Rc1, RcX};
use crate::verify::{ClientCertVerifier, NoClientAuth};
use crate::{NoKeyLog, compress, versions};

impl ConfigBuilder<ServerConfig, WantsVerifier> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: CfgX<dyn ClientCertVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ConfigBuilder {
            state: WantsServerCert {
                versions: self.state.versions,
                verifier: client_cert_verifier.into(),
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        self.with_client_cert_verifier(CfgX::new(NoClientAuth))
    }
}

/// A config builder state where the caller must supply how to provide a server certificate to
/// the connecting peer.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsServerCert {
    versions: versions::EnabledVersions,
    verifier: RcX<dyn ClientCertVerifier>,
}

impl ConfigBuilder<ServerConfig, WantsServerCert> {
    /// Sets a single certificate chain and matching private key.  This
    /// certificate and key is used for all subsequent connections,
    /// irrespective of things like SNI hostname.
    ///
    /// Note that the end-entity certificate must have the
    /// [Subject Alternative Name](https://tools.ietf.org/html/rfc6125#section-4.1)
    /// extension to describe, e.g., the valid DNS name. The `commonName` field is
    /// disregarded.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid, or if the
    /// `SubjectPublicKeyInfo` from the private key does not match the public
    /// key for the end-entity certificate from the `cert_chain`.
    pub fn with_single_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, self.crypto_provider())?;
        Ok(self.with_cert_resolver(CfgX::new(SingleCertAndKey::from(certified_key))))
    }

    /// Sets a single certificate chain, matching private key and optional OCSP
    /// response.  This certificate and key is used for all
    /// subsequent connections, irrespective of things like SNI hostname.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    /// `ocsp` is a DER-encoded OCSP response.  Ignored if zero length.
    ///
    /// This function fails if `key_der` is invalid, or if the
    /// `SubjectPublicKeyInfo` from the private key does not match the public
    /// key for the end-entity certificate from the `cert_chain`.
    pub fn with_single_cert_with_ocsp(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
        ocsp: Vec<u8>,
    ) -> Result<ServerConfig, Error> {
        let mut certified_key =
            CertifiedKey::from_der(cert_chain, key_der, self.crypto_provider())?;
        certified_key.ocsp = Some(ocsp);
        Ok(self.with_cert_resolver(CfgX::new(SingleCertAndKey::from(certified_key))))
    }

    /// Sets a custom [`ResolvesServerCert`].
    pub fn with_cert_resolver(self, cert_resolver: CfgX<dyn ResolvesServerCert>) -> ServerConfig {
        ServerConfig {
            provider: rcx_copy!(self.provider),
            verifier: self.state.verifier,
            cert_resolver: cfgx_into_cfgrcx!(cert_resolver),
            ignore_client_order: false,
            max_fragment_size: None,
            #[cfg(feature = "std")]
            session_storage: cfgrcx_new_from_cfgx!(handy::ServerSessionMemoryCache::new(256)),
            #[cfg(not(feature = "std"))]
            session_storage: cfgrc_with_cfg!(handy::NoServerSessionStorage {}),
            ticketer: cfgrc_with_cfg!(handy::NeverProducesTickets {}),
            alpn_protocols: Vec::new(),
            versions: self.state.versions,
            key_log: cfgrc_with_cfg!(NoKeyLog {}),
            enable_secret_extraction: false,
            max_early_data_size: 0,
            send_half_rtt_data: false,
            send_tls13_tickets: 2,
            #[cfg(feature = "tls12")]
            require_ems: cfg!(feature = "fips"),
            time_provider: rcx_into_cfgrc!(self.time_provider),
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: cfgrc_with_cfg!(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
        }
    }
}
