mod curves {
    pub mod ed25519;
    pub mod secp256k1;
}

mod utils {
    pub mod formats;
}

use crate::curves::{ed25519, secp256k1};

fn main() {
    // Ed25519 operations
    ed25519::process();

    // Secp256k1 operations
    secp256k1::process();
}
