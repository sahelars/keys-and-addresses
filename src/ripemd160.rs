use base58::ToBase58;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn compute_ripemd160_address(public_key_bytes_65: &[u8]) -> String {
    let sha256_hash = Sha256::digest(public_key_bytes_65); // Perform SHA-256 hashing on the public key

    let ripemd160_hash = Ripemd160::digest(&sha256_hash); // Perform RIPEMD-160 hashing on the SHA-256 hash

    let mut byte = vec![0x00]; // Create 1-byte vector
    byte.extend_from_slice(&ripemd160_hash); // Append the 20-byte RIPEMD-160 hash

    // Perform SHA-256 hashing twice on the 21-byte array
    let sha256_hash1 = Sha256::digest(&byte); // First SHA-256 hash
    let sha256_hash2 = Sha256::digest(&sha256_hash1); // Second SHA-256 hash

    let checksum = &sha256_hash2[..4]; // Extract the first 4 bytes of the second SHA-256 hash as a checksum

    // Append the checksum to the 21-byte array
    let mut address_with_checksum = byte;
    address_with_checksum.extend_from_slice(checksum);

    address_with_checksum.to_base58() // Encode the final 25-byte array in Base58
}
