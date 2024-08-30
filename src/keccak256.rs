use tiny_keccak::{Hasher, Keccak};

pub fn compute_keccak256_address(public_key_bytes_65: &[u8]) -> [u8; 20] {
    let mut hasher = Keccak::v256(); // Initialize the Keccak-256 hasher

    hasher.update(&public_key_bytes_65[1..]); // Skip the 0x04 prefix and update the hasher with the 65-byte public key

    let mut hash = [0u8; 32]; // Buffer to hold the 32-byte hash
    hasher.finalize(&mut hash); // Compute the hash and store the result in a 32-byte array

    let mut address = [0u8; 20]; // Buffer to hold the 20-byte address
    address.copy_from_slice(&hash[12..]); // Fill the buffer by extracting the last 20 bytes of the Keccak-256 hash
    address
}
