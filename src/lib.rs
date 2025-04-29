use sha3::{Digest, Sha3_256};

/// Hash a byte array using SHA3-256 and return the hash as a hex-encoded string (lowercase).
pub fn digest(bytes: &[u8]) -> String {
    return hex::encode(sha3_256_hash(bytes));
}

/// Hash a byte array using the SHA3-256 (kekkac) hashing algorithm.
pub fn sha3_256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result[..].to_vec()
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_works() {
        let result = digest(b"testing 123");
        assert_eq!(result, "f76ca65440e70c26774fa8969282af8681311c10f6f58e39b63351746dc3973e");
    }
}
