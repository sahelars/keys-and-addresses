# Keys and Addresses

Generating blockchain keys and addresses for popular cryptocurrencies like Solana, Bitcoin, and Ethereum.

- **Solana**: Generate key pairs using the Ed25519 algorithm.
- **Bitcoin**: Generate key pairs using the Secp256k1 algorithm, convert private keys to Wallet Import Format (WIF) using SHA-256 and Base58 encoding, and compute addresses using SHA-256 and RIPEMD-160 hashing.
- **Ethereum**: Compute Ethereum addresses from Secp256k1 public keys using Keccak-256 hashing and apply a mixed-case checksum.

## Project Structure

- `src/curves/ed25519.rs`: Generates and handles Ed25519 keys for Solana.
- `src/curves/secp256k1.rs`: Generates and handles Secp256k1 keys for Bitcoin and Ethereum.
- `src/utils/formats.rs`: For formatting a key into an Ethereum mixed-case checksum address, a hexadecimal address, a Bitcoin P2PKH address, and a Bitcoin WIF private key.

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

## Security Considerations

When working with cryptographic keys and sensitive data, it is crucial to follow best practices to prevent accidental exposure through memory leaks, timing side-channels, or other vulnerabilities. This section outlines key security measures implemented in the code, including zeroizing sensitive data and considerations for Base58 encoding.

### 1. Zeroizing Sensitive Data

Sensitive data, such as private keys and secret keys, can remain in memory after use, posing a significant security risk. If this data is not securely erased, it could be exposed through various methods, including:

- **Memory Dumps**: Attackers or malicious software could access memory dumps to extract sensitive information if data is not properly cleared.
- **Debugging Sessions**: During debugging, unzeroized sensitive data can be inadvertently exposed to developers or unauthorized users.
- **Crash Reports**: Applications that collect crash reports might inadvertently capture and send sensitive data if it is not zeroized.
- **Heap or Stack Leaks**: Sensitive data could persist on the heap or stack, making it susceptible to access by other processes or threads.

**Best Practices for Zeroizing:**

- **Zeroize After Use**: Always zeroize buffers and variables holding sensitive data once they are no longer needed. This minimizes the window of opportunity for potential exposure.
- **Use zeroize Crate**: In Rust, the zeroize crate provides a reliable way to securely erase data from memory. Applying zeroize() on sensitive buffers ensures that the data is overwritten, reducing the risk of lingering sensitive information.

**Example:**

```rust
use zeroize::Zeroize;

// Buffer for sensitive data
let mut private_key_bytes = [0u8; 32];

// Fill private key buffer and use for cryptographic operations...

// Zeroize the private key after use
private_key_bytes.zeroize();
```

### 2. Timing Side-Channel Risks with Base58 Encoding

Timing side-channels are vulnerabilities where an attacker gains information based on the time it takes to perform certain operations. Encoding sensitive data using functions that are not constant-time, such as Base58 encoding, can potentially leak information through timing variations.

**Considerations for Base58 Encoding:**

- **Non-Constant Time Operations**: Standard Base58 encoding implementations are typically not constant-time, meaning the processing time can vary based on the input data. This variability can be exploited by attackers through timing analysis.
- **Applicability**: Timing side-channel risks are more critical in scenarios where encoding operations are exposed to external timing measurements, such as remote API calls or shared environments.

**Mitigation Strategies:**

- **Avoid Base58 for Sensitive Data**: Where possible, avoid encoding private keys and other sensitive data directly with Base58. Prefer formats and methods that do not involve variable-time operations.
- **Use Constant-Time Alternatives**: If Base58 encoding is necessary, consider using constant-time alternatives or libraries designed with security in mind.
- **Limit Exposure**: Conduct sensitive operations, including encoding, in secure environments that minimize exposure to potential attackers.

**Example of Potential Risk:**

```rust
use base58::ToBase58;

// Encoding sensitive data directly can introduce timing side-channel vulnerabilities
let private_key_base58 = private_key_bytes.to_base58(); // This may be susceptible to timing attacks

// Mitigation: Avoid encoding private keys directly
```
