use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;

pub struct Ed25519 {
    pub secret_key: [u8; 64],
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

pub fn process() -> Ed25519 {
    // Initialize a cryptographically secure random number generator and create random 64-byte array
    let mut csprng = OsRng {}; // Generate the secure random number
    let mut random_bytes_64 = [0u8; 64]; // Buffer for 64-byte array
    csprng.fill_bytes(&mut random_bytes_64); // Fill the buffer with random bytes

    // Generate a private key scalar (seed for public key derivation) using the secure random 64-byte array
    let private_key_scalar = Scalar::from_bytes_mod_order_wide(&random_bytes_64); // Securely generate a scalar value

    // Derive the public key from the private key scalar by multiplying with the curve's base point
    let public_key_point: EdwardsPoint = &private_key_scalar * &ED25519_BASEPOINT_POINT; // Perform scalar multiplication with the base point of the ed25519 curve to get the public key point

    // Encode the public key point into compressed byte representation
    let public_key_bytes_32 = public_key_point.compress().to_bytes(); // Get the compressed public key format (32 bytes)

    // Convert the scalar to its byte representation
    let private_key_bytes_32 = private_key_scalar.to_bytes(); // Convert the private key scalar to a 32-byte array

    // Combine the private key and public key into a 64-byte secret key format
    let mut secret_key_bytes_64 = [0u8; 64]; // Buffer to hold the 64-byte the secret key
    secret_key_bytes_64[..32].copy_from_slice(&private_key_bytes_32); // Copy 32-byte private key (first part)
    secret_key_bytes_64[32..].copy_from_slice(&public_key_bytes_32); // Copy 32-byte public key (second part)

    // Return the keys
    Ed25519 {
        secret_key: secret_key_bytes_64,
        private_key: private_key_bytes_32,
        public_key: public_key_bytes_32,
    }
}
