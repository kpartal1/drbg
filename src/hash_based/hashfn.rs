use aes::cipher::{
    consts::{U16, U32, U55},
    generic_array::GenericArray,
};
use sha2::digest::OutputSizeUser;

pub trait HashFn {
    const BLOCK_LEN: usize;
    const SEED_LEN: usize;
    const SECURITY_STRENGTH: usize;

    const MAX_NUMBER_OF_BYTES_PER_REQUEST: u32 = 1 << 19;
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;

    type Entropy: AsRef<[u8]>;
    type Nonce: AsRef<[u8]>;
    fn entropy_from_slice(slice: &[u8]) -> Self::Entropy;
    fn nonce_from_slice(slice: &[u8]) -> Self::Nonce;

    type Seed: Clone + AsRef<[u8]> + AsMut<[u8]>;
    fn seed_from_slice(slice: &[u8]) -> Self::Seed;

    type Hash: AsRef<[u8]>;
    fn hash(data: impl AsRef<[u8]>) -> Self::Hash;
}

pub struct Sha256;

impl HashFn for Sha256 {
    const BLOCK_LEN: usize = 32;
    const SEED_LEN: usize = 55;
    const SECURITY_STRENGTH: usize = 32;

    type Entropy = GenericArray<u8, U32>;
    type Nonce = GenericArray<u8, U16>;
    fn entropy_from_slice(slice: &[u8]) -> Self::Entropy {
        Self::Entropy::clone_from_slice(slice)
    }
    fn nonce_from_slice(slice: &[u8]) -> Self::Nonce {
        Self::Nonce::clone_from_slice(slice)
    }

    type Seed = GenericArray<u8, U55>;
    fn seed_from_slice(slice: &[u8]) -> Self::Seed {
        Self::Seed::clone_from_slice(slice)
    }

    type Hash = GenericArray<u8, <sha2::Sha256 as OutputSizeUser>::OutputSize>;
    fn hash(data: impl AsRef<[u8]>) -> Self::Hash {
        use sha2::Digest;
        sha2::Sha256::digest(data)
    }
}
