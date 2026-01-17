# SP 800-90A DRBGs Implemented in Rust

### ⚠️ SAFETY NOTE ⚠️
This library has not been safety tested, and as such is not guaranteed to be safe in any way. Use at your own risk.

## Example Usage
```rust
use kondrbg::{DrbgCtrAes256, DrbgPrHashSha256};
fn main() {
    // May panic
    let default = DrbgCtrAes256::default();
    
    // Explicit error handling
    let drbg = match DrbgCtrAes256::new() {
        Ok(drbg) => drbg,
        Err(e) => panic!("Failed to instantiate CTR DRBG: {e}"),
    }

    // Builder pattern
    let drbg = DrbgCtrAes256::builder()
        .entropy(CustomEntropy)
        .personalization_string(b"personalization")
        .reseed_interval(1 << 11)
        .build();
    let drbg = match drbg {
        Ok(drbg) => drbg,
        Err(e) => panic!("Failed to instantiate CTR DRBG: {e}"),
    }
    
    // Prediction resistant version
    let drbg = DrbgPrHashSha256::builder()
        .entropy(CustomEntropy)
        .personalization_string(b"personalization")
        .build();
    let drbg = match drbg {
        Ok(drbg) => drbg,
        Err(e) => panic!("Failed to instantiate Hash DRBG: {e}"),
    }

    // Getting 10,000 random bytes from DRBG
    let mut bytes = [0; 10_000];
    drbg.fill_bytes(&mut bytes);
    
    // With additional input
    drbg.fill_bytes_with_ai(&mut bytes, b"additional");
}
```
## List of Implemented DRBGs (all support prediction reistance)
- CTR DRBG with df
    - AES-128
    - AES-192
    - AES-256
- Hash DRBG
    - SHA-224
    - SHA-224/512
    - SHA-256
    - SHA-256/512
    - SHA-384
    - SHA-512
- HMAC DRBG
    - SHA-224
    - SHA-224/512
    - SHA-256
    - SHA-256/512
    - SHA-384
    - SHA-512