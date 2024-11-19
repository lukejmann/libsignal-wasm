use rand::thread_rng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use super::{KeyMaterial, Public, Secret};
use crate::Result;

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const PUBLIC_KEY_LENGTH: usize = 32; // X25519 public key is 32 bytes
    const SECRET_KEY_LENGTH: usize = 32; // X25519 secret key is 32 bytes
    const CIPHERTEXT_LENGTH: usize = 32; // The ephemeral public key
    const SHARED_SECRET_LENGTH: usize = 32; // X25519 shared secret is 32 bytes

    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        // Generate a random secret key
        let secret = StaticSecret::random_from_rng(thread_rng());
        let public = X25519Public::from(&secret);

        (
            KeyMaterial::new(public.as_bytes().to_vec().into_boxed_slice()),
            KeyMaterial::new(secret.to_bytes().to_vec().into_boxed_slice()),
        )
    }

    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (super::SharedSecret, super::RawCiphertext) {
        // Generate ephemeral keypair
        let ephemeral_secret = StaticSecret::random_from_rng(thread_rng());
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        // Convert recipient's public key
        let recipient_public = X25519Public::from(<[u8; 32]>::try_from(&pub_key[..]).unwrap());

        // Compute shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        (
            shared_secret.as_bytes().to_vec().into_boxed_slice(),
            ephemeral_public.as_bytes().to_vec().into_boxed_slice(),
        )
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<super::SharedSecret> {
        // Convert secret key
        let secret = StaticSecret::from(<[u8; 32]>::try_from(&secret_key[..]).unwrap());

        // Convert ephemeral public key from ciphertext
        let ephemeral_public = X25519Public::from(<[u8; 32]>::try_from(ciphertext).unwrap());

        // Compute shared secret
        let shared_secret = secret.diffie_hellman(&ephemeral_public);

        Ok(shared_secret.as_bytes().to_vec().into_boxed_slice())
    }
}
