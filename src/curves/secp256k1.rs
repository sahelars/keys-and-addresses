use crate::utils::formats::{Hex, MixedCaseChecksum, P2PKH, WIF};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use rand::rngs::OsRng;

pub fn process() {
    // Initialize a cryptographically secure random number generator
    let mut csprng = OsRng {}; // Generate the secure random number

    // Generate a private key scalar (seed for public key derivation) using the secure random number
    let private_key_scalar = Scalar::generate_vartime(&mut csprng); // Securely generate a scalar value

    // Derive the public key from the private key scalar by multiplying with the curve's base point
    let public_key_point = ProjectivePoint::GENERATOR * private_key_scalar; // Perform scalar multiplication with the base point of the curve to get the public key point

    // Encode the public key point into uncompressed and compressed byte representations
    let uncompressed_public_key = public_key_point.to_encoded_point(false); // Get the uncompressed public key format (65 bytes)
    let compressed_public_key = public_key_point.to_encoded_point(true); // Get the compressed public key format (33 bytes)
    let public_key_bytes_65 = uncompressed_public_key.as_bytes(); // Convert the uncompressed public key to a 65-byte array
    let public_key_bytes_33 = compressed_public_key.as_bytes(); // Convert the compressed public key to a 33-byte array

    // Convert the scalar to its byte representation
    let private_key_bytes_32 = private_key_scalar.to_bytes(); // Convert the private key scalar to a 32-byte array

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
    println!("Private Key (Hex): {}\n", private_key_bytes_32.hex());
    println!(
        "Uncompressed Public Key (Hex): {}\n",
        public_key_bytes_65.hex()
    );
    println!(
        "Compressed Public Key (Hex): {}\n",
        public_key_bytes_33.hex()
    );
    println!(
        "WIF Private Key (Base58): {}\n",
        private_key_bytes_32.to_vec().wif()
    );
    println!(
        "P2PKH Public Address (Base58): {}\n",
        public_key_bytes_65.p2pkh()
    );
    println!(
        "Mixed-Case Checksum Public Address (Hex): {}\n",
        public_key_bytes_65.mixed_case_checksum()
    );
}
