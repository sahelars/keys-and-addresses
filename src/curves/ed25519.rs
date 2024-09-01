use base58::ToBase58;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn process() {
    // Initialize a cryptographically secure random number generator and create random 64-byte array
    let mut csprng = OsRng {}; // Generate the secure random number
    let mut random_bytes_64 = [0u8; 64]; // Buffer for 64-byte array
    csprng.fill_bytes(&mut random_bytes_64); // Fill the buffer with random data

    // Generate a private key scalar (seed for public key derivation) using the secure random 64-byte array
    let private_key_scalar = Scalar::from_bytes_mod_order_wide(&random_bytes_64); // Securely generate a scalar value

    // Derive the public key from the private key scalar by multiplying with the curve's base point
    let public_key_point: EdwardsPoint = &private_key_scalar * &ED25519_BASEPOINT_POINT; // Multiply the base point by the private key scalar to derive the public key point

    // Encode the public key point into compressed byte representation
    let public_key_bytes_32 = public_key_point.compress().to_bytes(); // Get the compressed public key format (32 bytes)

    // Convert the scalar to its byte representation
    let private_key_bytes_32 = private_key_scalar.to_bytes(); // Convert the private key scalar to a 32-byte array

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
