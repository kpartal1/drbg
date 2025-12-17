use aes::cipher::{
    consts::{U12, U16, U24, U32, U55, U111},
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

macro_rules! impl_sha {
    ($name:ident, $block_len:literal, $seed_len_c:literal, $seed_len:ident, $security_strength:literal, $entropy_len:ident, $nonce_len:ident) => {
        impl HashFn for sha2::$name {
            const BLOCK_LEN: usize = $block_len;
            const SEED_LEN: usize = $seed_len_c;
            const SECURITY_STRENGTH: usize = $security_strength;

            type Entropy = GenericArray<u8, $entropy_len>;
            type Nonce = GenericArray<u8, $nonce_len>;
            fn entropy_from_slice(slice: &[u8]) -> Self::Entropy {
                Self::Entropy::clone_from_slice(slice)
            }
            fn nonce_from_slice(slice: &[u8]) -> Self::Nonce {
                Self::Nonce::clone_from_slice(slice)
            }

            type Seed = GenericArray<u8, $seed_len>;
            fn seed_from_slice(slice: &[u8]) -> Self::Seed {
                Self::Seed::clone_from_slice(slice)
            }

            type Hash = GenericArray<u8, <Self as OutputSizeUser>::OutputSize>;
            fn hash(data: impl AsRef<[u8]>) -> Self::Hash {
                use sha2::Digest;
                Self::digest(data)
            }
        }
    };
}

impl_sha!(Sha224, 28, 55, U55, 24, U24, U12);
impl_sha!(Sha512_224, 28, 55, U55, 24, U24, U12);
impl_sha!(Sha256, 32, 55, U55, 32, U32, U16);
impl_sha!(Sha512_256, 32, 55, U55, 32, U32, U16);
impl_sha!(Sha384, 48, 111, U111, 32, U32, U16);
impl_sha!(Sha512, 64, 111, U111, 32, U32, U16);
