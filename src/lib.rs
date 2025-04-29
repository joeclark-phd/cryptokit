use k256::ecdsa::{signature::{Signer, Verifier}, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use rand_core::OsRng;

/// Hash a byte array using SHA3-256 and return the hash as a hex-encoded string (lowercase).
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(sha3_256_hash(bytes))
}

/// Hash a byte array using the SHA3-256 (kekkac) hashing algorithm.
pub fn sha3_256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result[..].to_vec()
}

/// A signing key is a secret key.  This one is created with the Secp256k1 algorithm.
/// Question: Is a `SigningKey` just a secret key, or does it have additional metadata?
pub fn create_secret_key() -> SigningKey {
    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`;
    signing_key
}

/// Derive the public key from the signing key.  This can be shared so clients can verify signatures.
pub fn derive_public_key(key: &SigningKey) -> VerifyingKey {
    VerifyingKey::from(key)
}

/// Produce a signature for a message using a secret key.
pub fn sign(message: &[u8], key: &SigningKey) -> Signature {
    key.sign(message)
}

/// Attempts to verify the signature on the message using the public key (verifying key) of the sender, returning true if valid.
pub fn signature_is_valid(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    key.verify(message, signature).is_ok()
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_works() {
        let result = digest(b"testing 123");
        assert_eq!(result, "f76ca65440e70c26774fa8969282af8681311c10f6f58e39b63351746dc3973e");
    }

    #[test]
    fn signing_works() {
        let private_key = create_secret_key();
        // Presumably the message (message body?) will be packaged with the digital signature and the sender's public key.
        // With those three things, the recipient can verify the signature, proving the message hasn't been tampered with.
        let message = b"Be sure to drink your Ovaltine";
        let signature = sign(message, &private_key);
        let public_key = derive_public_key(&private_key);
        // If the message hasn't been changed, the signature should be found valid:
        assert!(signature_is_valid(&public_key, message, &signature));
        // If the message has been tampered with, the signature should be found invalid:
        let different_message = b"Be sure to drink your Red Bull";
        assert!(!signature_is_valid(&public_key, different_message, &signature));
    }

}
