use base58::ToBase58;
use sha2::{Digest, Sha256};

pub fn convert_private_key_to_wif(private_key_bytes_32: &[u8; 32]) -> String {
    let mut extended_key = Vec::with_capacity(33); // Create a vector with capacity for the prefix and private key
    extended_key.push(0x80); // Prefix for private key (0x80)
    extended_key.extend_from_slice(private_key_bytes_32); // Add the 32-byte private key to the vector

    let mut sha256 = Sha256::new(); // Initialize SHA-256 hasher
    sha256.update(&extended_key); // Hash the extended key
    let hash1 = sha256.finalize(); // Finalize first hash

    sha256 = Sha256::new(); // Reinitialize SHA-256 hasher
    sha256.update(&hash1); // Hash the result of the first hash
    let hash2 = sha256.finalize(); // Finalize second hash

    extended_key.extend_from_slice(&hash2[..4]); // Append the first 4 bytes of the double SHA-256 hash as a checksum

    extended_key.to_base58() // Encode the extended key in Base58 format
}
