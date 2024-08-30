# Keys and Addresses

Generating blockchain keys and addresses for popular cryptocurrencies like Solana, Bitcoin, and Ethereum.

- **Solana**: Generate key pairs using the Ed25519 algorithm.
- **Bitcoin**: Generate public and private keys using the Secp256k1 algorithm, convert private keys to Wallet Import Format (WIF) using SHA-256 and Base58 encoding, and compute addresses using SHA-256 and RIPEMD-160 hashing functions.
- **Ethereum**: Compute Ethereum addresses from Secp256k1 public keys using the Keccak-256 hashing function.

## Project Structure

- `src/ed25519.rs`: Generates and handles Ed25519 keys for Solana.
- `src/secp256k1.rs`: Generates and handles Secp256k1 keys for Bitcoin and Ethereum.
- `src/wif.rs`: Converts private key to Bitcoin WIF format.
- `src/ripemd160.rs`: Computes RIPEMD-160 Bitcoin address.
- `src/keccak256.rs`: Computes Keccak-256 Ethereum address.

## Dependencies

This project relies on the following Rust crates:

- **base58**: Provides encoding and decoding base58 strings. [Crate](https://crates.io/crates/base58)
- **curve25519-dalek**: Provides Ed25519 elliptic curve operations used for Solana key generation. [Crate](https://crates.io/crates/curve25519-dalek)
- **k256**: Provides Secp256k1 elliptic curve operations used for Bitcoin and Ethereum key generation. [Crate](https://crates.io/crates/k256)
- **rand**: Provides secure random number generation utilities. [Crate](https://crates.io/crates/rand)
- **ripemd**: Provides RIPEMD hashing used for Bitcoin address computation. [Crate](https://crates.io/crates/ripemd)
- **sha2**: Provides SHA-256 hashing used for Bitcoin address computation. [Crate](https://crates.io/crates/sha2)
- **tiny-keccak**: Provides Keccak-256 hashing used for Ethereum address computation. [Crate](https://crates.io/crates/tiny-keccak)

## Usage

To run the key generation and address computation, execute the `main` function:

```
cargo run
```

## Data Breakdown

### Ed25519:

- Secret Key [u8; 64]: A 64-byte secret key used to derive both public and private keys.
- Private Key [u8; 32]: A 32-byte private key.
- Public Key [u8; 32]: A 32-byte public key derived from the private key.
- Secret Key (Base58): A Base58-encoded representation of the 64-byte secret key.
- Private Key (Base58): A Base58-encoded representation of the 32-byte private key.
- Public Key (Base58): A Base58-encoded representation of the 32-byte public key.

### Secp256k1:

- Private Key [u8; 32]: A 32-byte private key.
- Uncompressed Public Key [u8; 65]: A 65-byte uncompressed public key derived from the private key.
- Compressed Public Key [u8; 33]: A 33-byte compressed public key derived from the private key.
- Private Key WIF (Base58): A Base58-encoded representation of the private key following the Wallet Import Format (WIF).
- Private Key (Hex): A hexadecimal representation of the 32-byte private key.
- Uncompressed Public Key (Hex): A hexadecimal representation of the 65-byte uncompressed public key.
- Compressed Public Key (Hex): A hexadecimal representation of the 33-byte compressed public key.
- RIPEMD-160 Public Address (Base58): A Base58-encoded representation of an address derived from the public key. The process involves performing SHA-256 hashing on the public key, then RIPEMD-160 hashing on the SHA-256 result. A single byte is added to the RIPEMD-160 hash, followed by appending a checksum generated using double SHA-256.
- Keccak-256 Public Address (Hex): A hexadecimal representation of the address derived from the public key using Keccak-256 hashing.
