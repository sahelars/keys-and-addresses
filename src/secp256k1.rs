use crate::keccak256;
use crate::ripemd160;
use crate::wif;
use k256::ecdsa::SigningKey;
use rand::rngs::OsRng;

pub fn process() {
    // Generate a 32-byte private key using a secure random number generator
    let mut csprng = OsRng {}; // Generate the secure random number
    let signing_key = SigningKey::random(&mut csprng); // Generate a new private key
    let private_key_bytes_32 = signing_key.to_bytes(); // Get the private key as a 32-byte array

    // Create the WIF for the private key
    let private_key_wif = wif::convert_private_key_to_wif(&private_key_bytes_32.into()); // Convert the 32-byte private key to WIF

    // Derive the public key from the private key
    let uncompressed_public_key = signing_key.verifying_key().to_encoded_point(false); // Get the uncompressed public key format (65 bytes)
    let compressed_public_key = signing_key.verifying_key().to_encoded_point(true); // Get the compressed public key format (33 bytes)
    let public_key_bytes_65 = uncompressed_public_key.as_bytes(); // Convert the uncompressed public key to a 65-byte array
    let public_key_bytes_33 = compressed_public_key.as_bytes(); // Convert the compressed public key to a 33-byte array

    // Convert byte arrays to hexadecimal strings
    let private_key_hex = private_key_bytes_32
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>(); // Encode 32-byte private key to hexadecimal string
    let uncompressed_public_key_hex = public_key_bytes_65
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>(); // Encode 65-byte uncompressed public key to hexadecimal string
    let compressed_public_key_hex = public_key_bytes_33
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>(); // Encode 33-byte compressed public key to hexadecimal string

    // Create the RIPEMD-160 address
    let ripemd160_public_address_base58 =
        ripemd160::compute_ripemd160_address(&public_key_bytes_65); // Compute the address from the 65-byte public key using RIPEMD-160

    // Create the Keccak-256 address
    let public_address_bytes_20 = keccak256::compute_keccak256_address(&public_key_bytes_65); // Compute the address from the 65-byte public key using Keccak-256
    let keccak256_public_address_hex = format!(
        "0x{}",
        public_address_bytes_20
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    ); // Convert the 20-byte address to a hexadecimal string with "0x" prefix

    // Print the data
    println!("\nSecp256k1\n");
    println!("Private Key [u8; 32]: {:?}\n", private_key_bytes_32);
    println!(
        "Uncompressed Public Key [u8; 65]: {:?}\n",
        public_key_bytes_65
    );
    println!(
        "Compressed Public Key [u8; 33]: {:?}\n",
        public_key_bytes_33
    );
    println!("Private Key WIF (Base58): {}\n", private_key_wif);
    println!("Private Key (Hex): {}\n", private_key_hex);
    println!(
        "Uncompressed Public Key (Hex): {}\n",
        uncompressed_public_key_hex
    );
    println!(
        "Compressed Public Key (Hex): {}\n",
        compressed_public_key_hex
    );
    println!(
        "RIPEMD-160 Public Address (Base58): {}\n",
        ripemd160_public_address_base58
    );
    println!(
        "Keccak-256 Public Address (Hex): {}\n",
        keccak256_public_address_hex
    );
}
