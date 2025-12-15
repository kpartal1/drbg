use aes::cipher::{
    consts::{U8, U12, U16, U32, U40, U48},
    generic_array::GenericArray,
};

pub trait Cipher {
    const BLOCK_LEN: usize;
    const KEY_LEN: usize;
    const SEED_LEN: usize = Self::BLOCK_LEN + Self::KEY_LEN;

    const SECURITY_STRENGTH: usize;
    const MAX_NUMBER_OF_BYTES_PER_REQUEST: u32;
    const MAX_RESEED_INTERVAL: u64;

    type V: AsRef<[u8]> + AsMut<[u8]>;
    type Key;

    type Seed: AsRef<[u8]>;
    type Nonce;

    fn new(key: &Self::Key) -> Self;
    fn key_from_slice(slice: &[u8]) -> Self::Key;
    fn block_from_slice(slice: &[u8]) -> Self::V;
    fn seed_from_slice(slice: &[u8]) -> Self::Seed;
    fn nonce_from_slice(slice: &[u8]) -> Self::Nonce;

    fn block_encrypt(&self, block: &mut Self::V);
    fn block_encrypt_b2b(&self, block: &Self::V) -> Self::V;
}

macro_rules! impl_aes {
    ($cipher:ident, $inner:ident, $block_len:literal, $key_len:literal, $seed_len:ident, $nonce_len:ident) => {
        pub struct $cipher($inner);

        impl Cipher for $cipher {
            const BLOCK_LEN: usize = $block_len;
            const KEY_LEN: usize = $key_len;

            const SECURITY_STRENGTH: usize = Self::KEY_LEN;
            const MAX_NUMBER_OF_BYTES_PER_REQUEST: u32 = (1 << 19) / 8;
            const MAX_RESEED_INTERVAL: u64 = 1 << 48;

            type V = aes::Block;
            type Key = aes::cipher::Key<$inner>;

            type Seed = GenericArray<u8, $seed_len>;
            type Nonce = GenericArray<u8, $nonce_len>;

            fn new(key: &Self::Key) -> Self {
                use aes::cipher::KeyInit;
                Self($inner::new(key))
            }
            fn key_from_slice(slice: &[u8]) -> Self::Key {
                Self::Key::clone_from_slice(slice)
            }
            fn block_from_slice(slice: &[u8]) -> Self::V {
                Self::V::clone_from_slice(slice)
            }
            fn seed_from_slice(slice: &[u8]) -> Self::Seed {
                Self::Seed::clone_from_slice(slice)
            }
            fn nonce_from_slice(slice: &[u8]) -> Self::Nonce {
                Self::Nonce::clone_from_slice(slice)
            }

            fn block_encrypt(&self, block: &mut Self::V) {
                use aes::cipher::BlockEncrypt;
                self.0.encrypt_block(block);
            }
            fn block_encrypt_b2b(&self, block: &Self::V) -> Self::V {
                use aes::cipher::BlockEncrypt;
                let mut out_block = Self::V::default();
                self.0.encrypt_block_b2b(block, &mut out_block);
                out_block
            }
        }
    };
}

use aes::{Aes128Enc, Aes192Enc, Aes256Enc};
impl_aes!(Aes256, Aes256Enc, 16, 32, U48, U16);
impl_aes!(Aes192, Aes192Enc, 16, 24, U40, U12);
impl_aes!(Aes128, Aes128Enc, 16, 16, U32, U8);
