use base58::ToBase58;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub trait MixedCaseChecksum {
    fn mixed_case_checksum(self) -> String;
}

pub trait Hex {
    fn hex(self) -> String;
}

pub trait P2PKH {
    fn p2pkh(self) -> String;
}

pub trait WIF {
    fn wif(self) -> String;
}

impl MixedCaseChecksum for &[u8] {
    fn mixed_case_checksum(self) -> String {
        let mut hasher = Keccak::v256(); // Initialize the Keccak-256 hasher

        hasher.update(&self[1..]); // Skip the 0x04 prefix and update the hasher with the 65-byte public key

        let mut hash = [0u8; 32]; // Buffer to hold the 32-byte hash
        hasher.finalize(&mut hash); // Compute the hash and store the result in a 32-byte array

        let mut address = [0u8; 20]; // Buffer to hold the 20-byte address
        address.copy_from_slice(&hash[12..]); // Fill the buffer by extracting the last 20 bytes of the Keccak-256 hash

        format!(
            "0x{}",
            address
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        ) // Convert the 20-byte address to a hexadecimal string with "0x" prefix
    }
}

impl Hex for &[u8] {
    fn hex(self) -> String {
        self.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>() // Convert byte array to hex
    }
}

impl P2PKH for &[u8] {
    fn p2pkh(self) -> String {
        let sha256_hash = Sha256::digest(self); // Perform SHA-256 hashing on the public key

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
}

impl WIF for Vec<u8> {
    fn wif(self) -> String {
        let mut extended_key = Vec::with_capacity(33); // Create a vector with capacity for the prefix and private key
        extended_key.push(0x80); // Prefix for private key (0x80)
        extended_key.extend_from_slice(&self); // Add the 32-byte private key to the vector

        let mut sha256 = Sha256::new(); // Initialize SHA-256 hasher
        sha256.update(&extended_key); // Hash the extended key
        let hash1 = sha256.finalize(); // Finalize first hash

        sha256 = Sha256::new(); // Reinitialize SHA-256 hasher
        sha256.update(&hash1); // Hash the result of the first hash
        let hash2 = sha256.finalize(); // Finalize second hash

        extended_key.extend_from_slice(&hash2[..4]); // Append the first 4 bytes of the double SHA-256 hash as a checksum

        extended_key.to_base58() // Encode the extended key in Base58 format
    }
}
