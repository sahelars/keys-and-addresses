use base58::ToBase58;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub trait Hex {
    fn hex(self) -> String;
}

pub trait MixedCaseChecksum {
    fn mixed_case_checksum(self) -> String;
}

pub trait P2PKH {
    fn p2pkh(self) -> String;
}

pub trait WIF {
    fn wif(self) -> String;
}

impl Hex for &[u8] {
    fn hex(self) -> String {
        self.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>() // Convert byte array to hex
    }
}

impl MixedCaseChecksum for &[u8] {
    fn mixed_case_checksum(self) -> String {
        let public_key = &self[1..]; // Skip the 0x04 prefix

        let mut hasher = Keccak::v256(); // Initialize the Keccak-256 hasher
        hasher.update(public_key); // Hash the 64-byte public key
        let mut hash = [0u8; 32]; // Buffer to hold the 32-byte hash
        hasher.finalize(&mut hash); // Compute the hash and store the result in a 32-byte array

        let address = &hash[12..]; // Extract the last 20 bytes of the Keccak-256 hash to form the address

        let address_hex: String = address.iter().map(|b| format!("{:02x}", b)).collect(); // Convert the address to a lowercase hexadecimal string

        let mut checksum_hasher = Keccak::v256(); // Initialize another Keccak-256 hasher for checksum
        checksum_hasher.update(address_hex.as_bytes()); // Hash the lowercase hexadecimal string of the address
        let mut checksum_hash = [0u8; 32]; // Buffer to hold the 32-byte checksum hash
        checksum_hasher.finalize(&mut checksum_hash); // Compute the checksum hash and store the result in a 32-byte array

        // Apply mixed-case checksum logic directly during address formatting
        let checksummed_address: String = address_hex
            .chars()
            .enumerate()
            .map(|(i, c)| {
                // Determine which nibble of the checksum hash to use for character casing
                let hash_byte = checksum_hash[i / 2];
                let is_upper = if i % 2 == 0 {
                    (hash_byte >> 4) >= 8 // Use the high nibble for even indices
                } else {
                    (hash_byte & 0x0F) >= 8 // Use the low nibble for odd indices
                };

                // Convert the character to uppercase if required by the checksum
                if is_upper {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();

        format!("0x{}", checksummed_address) // Prepend the "0x" prefix to the checksummed address
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
