mod ed25519;
mod keccak256;
mod ripemd160;
mod secp256k1;
mod wif;

fn main() {
    // Ed25519 operations
    ed25519::process();

    // Secp256k1 operations
    secp256k1::process();
}
