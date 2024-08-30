use base58::ToBase58;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn process() {
    // Generate a 32-byte private key (seed) using a secure random number generator
    let mut csprng = OsRng {}; // Generate the secure random number
    let mut private_key_bytes_32 = [0u8; 32]; // Buffer to hold the 32-byte private key
    csprng.fill_bytes(&mut private_key_bytes_32); // Fill the buffer with random bytes

    // Create the field element for cryptographic operations
    let private_key_scalar = Scalar::from_bytes_mod_order(private_key_bytes_32); // Convert the 32-byte private key into a scalar

    // Derive the public key from the private key using the correct base point
    let public_key_point: EdwardsPoint = &private_key_scalar * &ED25519_BASEPOINT_POINT; // Compute public key point from private key
    let public_key_bytes_32 = public_key_point.compress().to_bytes(); // Compress the public key point and convert to a 32-byte array

    // Combine the private key and public key into a 64-byte secret key format
    let mut secret_key_bytes_64 = [0u8; 64]; // Buffer to hold the 64-byte the secret key
    secret_key_bytes_64[..32].copy_from_slice(&private_key_bytes_32); // Copy 32-byte private key (first part)
    secret_key_bytes_64[32..].copy_from_slice(&public_key_bytes_32); // Copy 32-byte public key (second part)

    // Convert byte arrays to Base58 strings
    let secret_key_base58 = secret_key_bytes_64.to_base58(); // Encode 64-byte secret key to Base58
    let private_key_base58 = private_key_bytes_32.to_base58(); // Encode 32-byte private key to Base58
    let public_key_base58 = public_key_bytes_32.to_base58(); // Encode 32-byte public key to Base58

    // Print the data
    println!("\nEd25519\n");
    println!("Secret Key [u8; 64]: {:?}\n", secret_key_bytes_64);
    println!("Private Key [u8; 32]: {:?}\n", private_key_bytes_32);
    println!("Public Key [u8; 32]: {:?}\n", public_key_bytes_32);
    println!("Secret Key (Base58): {}\n", secret_key_base58);
    println!("Private Key (Base58): {}\n", private_key_base58);
    println!("Public Key (Base58): {}\n", public_key_base58);
}
