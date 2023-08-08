use crate::crypto;
use crate::crypto::cipher::{
    make_nonce, make_tls13_aad, AeadKey, Iv, MessageDecrypter, MessageEncrypter,
};
use crate::crypto::hash;
use crate::enums::{CipherSuite, ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
use crate::suites::BulkAlgorithm;
#[cfg(feature = "secret_extraction")]
use crate::suites::ConnectionTrafficSecrets;
use crate::suites::{CipherSuiteCommon, SupportedCipherSuite};

use ring::aead;

use core::fmt;

pub(crate) mod key_schedule;

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        bulk: BulkAlgorithm::Chacha20Poly1305,
        hash_provider: &crypto::ring::hash::SHA256,
    },
    hmac_provider: &crypto::ring::hmac::HMAC_SHA256,
    aead_alg: &Chacha20Poly1305Aead(AeadAlgorithm(&ring::aead::CHACHA20_POLY1305)),
    #[cfg(feature = "quic")]
    confidentiality_limit: u64::MAX,
    #[cfg(feature = "quic")]
    integrity_limit: 1 << 36,
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            bulk: BulkAlgorithm::Aes256Gcm,
            hash_provider: &crypto::ring::hash::SHA384,
        },
        hmac_provider: &crypto::ring::hmac::HMAC_SHA384,
        aead_alg: &Aes256GcmAead(AeadAlgorithm(&ring::aead::AES_256_GCM)),
        #[cfg(feature = "quic")]
        confidentiality_limit: 1 << 23,
        #[cfg(feature = "quic")]
        integrity_limit: 1 << 52,
    });

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        bulk: BulkAlgorithm::Aes128Gcm,
        hash_provider: &crypto::ring::hash::SHA256,
    },
    hmac_provider: &crypto::ring::hmac::HMAC_SHA256,
    aead_alg: &Aes128GcmAead(AeadAlgorithm(&ring::aead::AES_128_GCM)),
    #[cfg(feature = "quic")]
    confidentiality_limit: 1 << 23,
    #[cfg(feature = "quic")]
    integrity_limit: 1 << 52,
};

/// A TLS 1.3 cipher suite supported by rustls.
pub struct Tls13CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,
    pub(crate) hmac_provider: &'static dyn crypto::hmac::Hmac,
    pub(crate) aead_alg: &'static dyn Tls13AeadAlgorithm,
    #[cfg(feature = "quic")]
    pub(crate) confidentiality_limit: u64,
    #[cfg(feature = "quic")]
    pub(crate) integrity_limit: u64,
}

impl Tls13CipherSuite {
    /// Can a session using suite self resume from suite prev?
    pub fn can_resume_from(&self, prev: &'static Self) -> Option<&'static Self> {
        (prev.common.hash_provider.algorithm() == self.common.hash_provider.algorithm())
            .then(|| prev)
    }
}

impl From<&'static Tls13CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls13CipherSuite) -> Self {
        Self::Tls13(s)
    }
}

impl PartialEq for Tls13CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for Tls13CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13CipherSuite")
            .field("suite", &self.common.suite)
            .field("bulk", &self.common.bulk)
            .finish()
    }
}

struct Chacha20Poly1305Aead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        let (key, iv) = (slice_to_array(key.as_ref()), slice_to_array(&iv.0));
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

struct Aes256GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        let (key, salt, iv) = slices_to_arrays(key.as_ref(), &iv.0[..4], &iv.0[4..]);
        ConnectionTrafficSecrets::Aes256Gcm { key, salt, iv }
    }
}

struct Aes128GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        let (key, salt, iv) = slices_to_arrays(key.as_ref(), &iv.0[..4], &iv.0[4..]);
        ConnectionTrafficSecrets::Aes128Gcm { key, salt, iv }
    }
}

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static ring::aead::Algorithm);

impl AeadAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Tls13MessageDecrypter {
            dec_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

pub(crate) trait Tls13AeadAlgorithm: Send + Sync {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter>;
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter>;
    fn key_len(&self) -> usize;

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets;
}

struct Tls13MessageEncrypter {
    enc_key: ring::aead::LessSafeKey,
    iv: Iv,
}

struct Tls13MessageDecrypter {
    dec_key: ring::aead::LessSafeKey,
    iv: Iv,
}

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);
        msg.typ.encode(&mut payload);

        let nonce = aead::Nonce::assume_unique_for_key(make_nonce(&self.iv, seq));
        let aad = aead::Aad::from(make_tls13_aad(total_len));

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        Ok(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        })
    }
}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = &mut msg.payload.0;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(make_nonce(&self.iv, seq));
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

#[cfg(feature = "secret_extraction")]
fn slices_to_arrays<const NK: usize, const NS: usize, const NI: usize>(
    k: &[u8],
    s: &[u8],
    i: &[u8],
) -> ([u8; NK], [u8; NS], [u8; NI]) {
    (slice_to_array(k), slice_to_array(s), slice_to_array(i))
}

#[cfg(feature = "secret_extraction")]
fn slice_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    // this is guaranteed true because `ConnectionTrafficSecrets` items and
    // `key_len()` are in agreement.
    debug_assert_eq!(N, slice.len());
    slice.try_into().unwrap()
}

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_client_verify_message(handshake_hash: &hash::Output) -> Vec<u8> {
    construct_verify_message(handshake_hash, b"TLS 1.3, client CertificateVerify\x00")
}

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_server_verify_message(handshake_hash: &hash::Output) -> Vec<u8> {
    construct_verify_message(handshake_hash, b"TLS 1.3, server CertificateVerify\x00")
}

fn construct_verify_message(
    handshake_hash: &hash::Output,
    context_string_with_0: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.resize(64, 0x20u8);
    msg.extend_from_slice(context_string_with_0);
    msg.extend_from_slice(handshake_hash.as_ref());
    msg
}
