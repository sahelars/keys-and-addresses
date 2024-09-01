mod curves {
    pub mod ed25519;
    pub mod secp256k1;
}

mod utils {
    pub mod formats;
}

use crate::curves::{ed25519, secp256k1};
use crate::utils::formats::{Hex, MixedCaseChecksum, P2PKH, WIF};
use base58::ToBase58;

fn main() {
    // Ed25519 operations
    let ed25519_keys = ed25519::process();

    // Print Ed25519 data
    println!("\nEd25519\n");
    println!("Secret Key [u8; 64]: {:?}\n", ed25519_keys.secret_key);
    println!("Private Key [u8; 32]: {:?}\n", ed25519_keys.private_key);
    println!("Public Key [u8; 32]: {:?}\n", ed25519_keys.public_key);
    println!(
        "Secret Key (Base58): {}\n",
        ed25519_keys.secret_key.to_base58()
    );
    println!(
        "Private Key (Base58): {}\n",
        ed25519_keys.private_key.to_base58()
    );
    println!(
        "Public Key (Base58): {}\n",
        ed25519_keys.public_key.to_base58()
    );

    // Secp256k1 operations
    let secp256k1_keys = secp256k1::process();

    // Print Secp256k1 data
    println!("\nSecp256k1\n");
    println!("Private Key [u8; 32]: {:?}\n", secp256k1_keys.private_key);
    println!(
        "Uncompressed Public Key [u8; 65]: {:?}\n",
        secp256k1_keys.uncompressed_public_key
    );
    println!(
        "Compressed Public Key [u8; 33]: {:?}\n",
        secp256k1_keys.compressed_public_key
    );
    println!("Private Key (Hex): {}\n", secp256k1_keys.private_key.hex());
    println!(
        "Uncompressed Public Key (Hex): {}\n",
        secp256k1_keys.uncompressed_public_key.hex()
    );
    println!(
        "Compressed Public Key (Hex): {}\n",
        secp256k1_keys.compressed_public_key.hex()
    );
    println!(
        "Mixed-Case Checksum Public Address (Hex): {}\n",
        secp256k1_keys.uncompressed_public_key.mixed_case_checksum()
    );
    println!(
        "WIF Private Key (Base58): {}\n",
        secp256k1_keys.private_key.wif()
    );
    println!(
        "P2PKH Public Address (Base58): {}\n",
        secp256k1_keys.uncompressed_public_key.p2pkh()
    );
}
