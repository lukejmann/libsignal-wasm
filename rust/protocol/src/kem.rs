//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod x25519;

use std::marker::PhantomData;
use std::ops::Deref;

use derive_where::derive_where;
use displaydoc::Display;
use subtle::ConstantTimeEq;

use crate::{Result, SignalProtocolError};

type SharedSecret = Box<[u8]>;

// The difference between the two is that the raw one does not contain the KeyType byte prefix.
pub(crate) type RawCiphertext = Box<[u8]>;
pub type SerializedCiphertext = Box<[u8]>;

/// Each KEM supported by libsignal-protocol implements this trait.
///
/// Similar to the traits in RustCrypto's [kem](https://docs.rs/kem/) crate.
///
/// # Example
/// ```ignore
/// struct MyNiftyKEM;
/// # #[cfg(ignore_even_when_running_all_tests)]
/// impl Parameters for MyNiftyKEM {
///     // ...
/// }
/// ```
trait Parameters {
    const PUBLIC_KEY_LENGTH: usize;
    const SECRET_KEY_LENGTH: usize;
    const CIPHERTEXT_LENGTH: usize;
    const SHARED_SECRET_LENGTH: usize;
    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>);
    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (SharedSecret, RawCiphertext);
    fn decapsulate(secret_key: &KeyMaterial<Secret>, ciphertext: &[u8]) -> Result<SharedSecret>;
}

/// Acts as a bridge between the static [Parameters] trait and the dynamic [KeyType] enum.
trait DynParameters {
    fn public_key_length(&self) -> usize;
    fn secret_key_length(&self) -> usize;
    fn ciphertext_length(&self) -> usize;
    #[allow(dead_code)]
    fn shared_secret_length(&self) -> usize;
    fn generate(&self) -> (KeyMaterial<Public>, KeyMaterial<Secret>);
    fn encapsulate(&self, pub_key: &KeyMaterial<Public>) -> (SharedSecret, RawCiphertext);
    fn decapsulate(
        &self,
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<SharedSecret>;
}

impl<T: Parameters> DynParameters for T {
    fn public_key_length(&self) -> usize {
        Self::PUBLIC_KEY_LENGTH
    }

    fn secret_key_length(&self) -> usize {
        Self::SECRET_KEY_LENGTH
    }

    fn ciphertext_length(&self) -> usize {
        Self::CIPHERTEXT_LENGTH
    }

    fn shared_secret_length(&self) -> usize {
        Self::SHARED_SECRET_LENGTH
    }

    fn generate(&self) -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        Self::generate()
    }

    fn encapsulate(&self, pub_key: &KeyMaterial<Public>) -> (SharedSecret, RawCiphertext) {
        Self::encapsulate(pub_key)
    }

    fn decapsulate(
        &self,
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<SharedSecret> {
        Self::decapsulate(secret_key, ciphertext)
    }
}

/// Designates a supported KEM protocol
#[derive(Display, Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    /// X25519 key
    X25519,
    // /// Kyber768 key
    // #[cfg(any(feature = "kyber768", test))]
    // Kyber768,
    // /// Kyber1024 key
    // Kyber1024,
    // /// ML-KEM 1024 key
    // #[cfg(feature = "mlkem1024")]
    // MLKEM1024,
}

impl KeyType {
    fn value(&self) -> u8 {
        match self {
            KeyType::X25519 => 0x01,
            // #[cfg(any(feature = "kyber768", test))]
            // KeyType::Kyber768 => 0x07,
            // KeyType::Kyber1024 => 0x08,
            // #[cfg(feature = "mlkem1024")]
            // KeyType::MLKEM1024 => 0x0A,
        }
    }

    /// Allows KeyType to act like `&dyn Parameters` while still being represented by a single byte.
    ///
    /// Declared `const` to encourage inlining.
    const fn parameters(&self) -> &'static dyn DynParameters {
        match self {
            KeyType::X25519 => &x25519::Parameters,
            // #[cfg(any(feature = "kyber768", test))]
            // KeyType::Kyber768 => &kyber768::Parameters,
            // KeyType::Kyber1024 => &kyber1024::Parameters,
            // #[cfg(feature = "mlkem1024")]
            // KeyType::MLKEM1024 => &mlkem1024::Parameters,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: u8) -> Result<Self> {
        match x {
            0x01 => Ok(KeyType::X25519),
            // #[cfg(any(feature = "kyber768", test))]
            // 0x07 => Ok(KeyType::Kyber768),
            // 0x08 => Ok(KeyType::Kyber1024),
            // #[cfg(feature = "mlkem1024")]
            // 0x0A => Ok(KeyType::MLKEM1024),
            t => Err(SignalProtocolError::BadKEMKeyType(t)),
        }
    }
}

pub trait KeyKind {
    fn key_length(key_type: KeyType) -> usize;
}

pub enum Public {}

impl KeyKind for Public {
    fn key_length(key_type: KeyType) -> usize {
        key_type.parameters().public_key_length()
    }
}

pub enum Secret {}

impl KeyKind for Secret {
    fn key_length(key_type: KeyType) -> usize {
        key_type.parameters().secret_key_length()
    }
}

#[derive_where(Clone)]
pub(crate) struct KeyMaterial<T: KeyKind> {
    data: Box<[u8]>,
    kind: PhantomData<T>,
}

impl<T: KeyKind> KeyMaterial<T> {
    fn new(data: Box<[u8]>) -> Self {
        KeyMaterial {
            data,
            kind: PhantomData,
        }
    }
}

impl<T: KeyKind> Deref for KeyMaterial<T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.deref()
    }
}

#[derive_where(Clone)]
pub struct Key<T: KeyKind> {
    key_type: KeyType,
    key_data: KeyMaterial<T>,
}

impl<T: KeyKind> Key<T> {
    /// Create a `Key<Kind>` instance from a byte string created with the
    /// function `Key<Kind>::serialize(&self)`.
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        if value.len() != T::key_length(key_type) + 1 {
            return Err(SignalProtocolError::BadKEMKeyLength(key_type, value.len()));
        }
        Ok(Key {
            key_type,
            key_data: KeyMaterial::new(value[1..].into()),
        })
    }
    /// Create a binary representation of the key that includes a protocol identifier.
    pub fn serialize(&self) -> Box<[u8]> {
        let mut result = Vec::with_capacity(1 + self.key_data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(&self.key_data);
        result.into_boxed_slice()
    }

    /// Return the `KeyType` that identifies the KEM protocol for this key.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

impl Key<Public> {
    /// Create a `SharedSecret` and a `Ciphertext`. The `Ciphertext` can be safely sent to the
    /// holder of the corresponding `SecretKey` who can then use it to `decapsulate` the same
    /// `SharedSecret`.
    pub fn encapsulate(&self) -> (SharedSecret, SerializedCiphertext) {
        let (ss, ct) = self.key_type.parameters().encapsulate(&self.key_data);
        (
            ss,
            Ciphertext {
                key_type: self.key_type,
                data: &ct,
            }
            .serialize(),
        )
    }
}

impl Key<Secret> {
    /// Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` by a holder of
    /// the corresponding `PublicKey`.
    pub fn decapsulate(&self, ct_bytes: &SerializedCiphertext) -> Result<Box<[u8]>> {
        // deserialization checks that the length is correct for the KeyType
        let ct = Ciphertext::deserialize(ct_bytes)?;
        if ct.key_type != self.key_type {
            return Err(SignalProtocolError::WrongKEMKeyType(
                ct.key_type.value(),
                self.key_type.value(),
            ));
        }
        self.key_type
            .parameters()
            .decapsulate(&self.key_data, ct.data)
    }
}

impl TryFrom<&[u8]> for Key<Public> {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl TryFrom<&[u8]> for Key<Secret> {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for Key<Public> {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        if self.key_type != other.key_type {
            return 0.ct_eq(&1);
        }
        self.key_data.ct_eq(&other.key_data)
    }
}

impl PartialEq for Key<Public> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Key<Public> {}

/// A KEM public key with the ability to encapsulate a shared secret.
pub type PublicKey = Key<Public>;

/// A KEM secret key with the ability to decapsulate a shared secret.
pub type SecretKey = Key<Secret>;

/// A public/secret key pair for a KEM protocol.
#[derive(Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Creates a public-secret key pair for a specified KEM protocol. Uses system randomness
    /// [implemented by PQClean](https://github.com/PQClean/PQClean/blob/c1b19a865de329e87e9b3e9152362fcb709da8ab/common/randombytes.c#L335).
    pub fn generate(key_type: KeyType) -> Self {
        let (pk, sk) = key_type.parameters().generate();
        Self {
            secret_key: SecretKey {
                key_type,
                key_data: sk,
            },
            public_key: PublicKey {
                key_type,
                key_data: pk,
            },
        }
    }

    pub fn new(public_key: PublicKey, secret_key: SecretKey) -> Self {
        assert_eq!(public_key.key_type, secret_key.key_type);
        Self {
            public_key,
            secret_key,
        }
    }

    /// Deserialize public and secret keys that were serialized by `PublicKey::serialize()`
    /// and `SecretKey::serialize()` respectively.
    pub fn from_public_and_private(public_key: &[u8], secret_key: &[u8]) -> Result<Self> {
        let public_key = PublicKey::try_from(public_key)?;
        let secret_key = SecretKey::try_from(secret_key)?;
        if public_key.key_type != secret_key.key_type {
            Err(SignalProtocolError::WrongKEMKeyType(
                secret_key.key_type.value(),
                public_key.key_type.value(),
            ))
        } else {
            Ok(Self {
                public_key,
                secret_key,
            })
        }
    }
}

/// Utility type to handle serialization and deserialization of ciphertext data
struct Ciphertext<'a> {
    key_type: KeyType,
    data: &'a [u8],
}

impl<'a> Ciphertext<'a> {
    /// Create a `Ciphertext` instance from a byte string created with the
    /// function `Ciphertext::serialize(&self)`.
    pub fn deserialize(value: &'a [u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        if value.len() != key_type.parameters().ciphertext_length() + 1 {
            return Err(SignalProtocolError::BadKEMCiphertextLength(
                key_type,
                value.len(),
            ));
        }
        Ok(Ciphertext {
            key_type,
            data: &value[1..],
        })
    }

    /// Create a binary representation of the key that includes a protocol identifier.
    pub fn serialize(&self) -> SerializedCiphertext {
        let mut result = Vec::with_capacity(1 + self.data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(self.data);
        result.into_boxed_slice()
    }
}
