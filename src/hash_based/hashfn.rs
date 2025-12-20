use aes::cipher::{
    consts::{U55, U111},
    generic_array::GenericArray,
};
use sha2::digest::OutputSizeUser;

pub trait HashFn {
    const BLOCK_LEN: usize;
    const SEED_LEN: usize;
    const SECURITY_STRENGTH: usize;

    const MAX_RESEED_INTERVAL: u64 = 1 << 48;

    type Seed: Clone + AsRef<[u8]> + AsMut<[u8]>;
    fn seed_from_slice(slice: &[u8]) -> Self::Seed;

    type Hash: AsRef<[u8]>;
    fn hash_from_slice(slice: &[u8]) -> Self::Hash;
    fn hash(data: impl AsRef<[u8]>) -> Self::Hash;
    fn hmac(key: &Self::Hash, input: &[u8]) -> Self::Hash;
}

macro_rules! impl_sha {
    ($name:ident, $block_len:literal, $seed_len_c:literal, $seed_len:ident, $security_strength:literal) => {
        impl HashFn for sha2::$name {
            const BLOCK_LEN: usize = $block_len;
            const SEED_LEN: usize = $seed_len_c;
            const SECURITY_STRENGTH: usize = $security_strength;

            type Seed = GenericArray<u8, $seed_len>;
            fn seed_from_slice(slice: &[u8]) -> Self::Seed {
                Self::Seed::clone_from_slice(slice)
            }

            type Hash = GenericArray<u8, <Self as OutputSizeUser>::OutputSize>;
            fn hash_from_slice(slice: &[u8]) -> Self::Hash {
                Self::Hash::clone_from_slice(slice)
            }
            fn hash(data: impl AsRef<[u8]>) -> Self::Hash {
                use sha2::Digest;
                Self::digest(data)
            }
            fn hmac(key: &Self::Hash, input: &[u8]) -> Self::Hash {
                use hmac::{Hmac, Mac};
                let mut hmac =
                    Hmac::<Self>::new_from_slice(key).expect("HMAC can take key of any size");
                hmac.update(input);
                Self::hash_from_slice(&hmac.finalize().into_bytes())
            }
        }
    };
}

impl_sha!(Sha224, 28, 55, U55, 24);
impl_sha!(Sha512_224, 28, 55, U55, 24);
impl_sha!(Sha256, 32, 55, U55, 32);
impl_sha!(Sha512_256, 32, 55, U55, 32);
impl_sha!(Sha384, 48, 111, U111, 32);
impl_sha!(Sha512, 64, 111, U111, 32);
