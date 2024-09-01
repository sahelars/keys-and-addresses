use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use rand::rngs::OsRng;

pub struct Secp256k1 {
    pub private_key: [u8; 32],
    pub uncompressed_public_key: [u8; 65],
    pub compressed_public_key: [u8; 33],
}

pub fn process() -> Secp256k1 {
    // Initialize a cryptographically secure random number generator
    let mut csprng = OsRng {}; // Generate the secure random number

    // Generate a private key scalar (seed for public key derivation) using the secure random number
    let private_key_scalar = Scalar::generate_vartime(&mut csprng); // Securely generate a scalar value

    // Derive the public key from the private key scalar by multiplying with the curve's base point
    let public_key_point = ProjectivePoint::GENERATOR * private_key_scalar; // Perform scalar multiplication with the base point of the curve to get the public key point

    // Encode the public key point into uncompressed and compressed byte representations
    let public_key_bytes_65 = public_key_point.to_encoded_point(false).as_bytes().try_into().unwrap(); // Get the uncompressed public key format (65 bytes)
    let public_key_bytes_33 = public_key_point.to_encoded_point(true).as_bytes().try_into().unwrap(); // Get the compressed public key format (33 bytes)

    // Convert the scalar to its byte representation
    let private_key_bytes_32: [u8; 32] = private_key_scalar.to_bytes().into(); // Convert the private key scalar to a 32-byte array

    // Return the keys
    Secp256k1 {
        private_key: private_key_bytes_32,
        uncompressed_public_key: public_key_bytes_65,
        compressed_public_key: public_key_bytes_33,
    }
}
