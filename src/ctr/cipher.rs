use aes::cipher::{
    consts::{U32, U40, U48},
    generic_array::GenericArray,
};

pub trait Cipher {
    const BLOCK_LEN: usize;
    const KEY_LEN: usize;
    const SEED_LEN: usize = Self::BLOCK_LEN + Self::KEY_LEN;

    const SECURITY_STRENGTH: usize;
    const MAX_NUMBER_OF_BYTES_PER_REQUEST: u32;
    const MAX_RESEED_INTERVAL: u64;

    type Block: AsRef<[u8]> + AsMut<[u8]>;
    type Key: AsRef<[u8]>;
    fn block_from_slice(slice: &[u8]) -> Self::Block;
    fn key_from_slice(slice: &[u8]) -> Self::Key;

    type Seed: AsRef<[u8]> + AsMut<[u8]>;
    fn seed_from_slice(slice: &[u8]) -> Self::Seed;
    fn seed_to_key_block(seed: Self::Seed) -> (Self::Key, Self::Block) {
        let seed = seed.as_ref();
        (
            Self::key_from_slice(&seed[..Self::KEY_LEN]),
            Self::block_from_slice(&seed[Self::KEY_LEN..]),
        )
    }

    fn new(key: &Self::Key) -> Self;
    fn block_encrypt(&self, block: &mut Self::Block);
    fn block_encrypt_b2b(&self, block: &Self::Block) -> Self::Block;
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

            type Block = aes::Block;
            type Key = aes::cipher::Key<$inner>;
            fn block_from_slice(slice: &[u8]) -> Self::Block {
                Self::Block::clone_from_slice(slice)
            }
            fn key_from_slice(slice: &[u8]) -> Self::Key {
                Self::Key::clone_from_slice(slice)
            }

            type Seed = GenericArray<u8, $seed_len>;
            fn seed_from_slice(slice: &[u8]) -> Self::Seed {
                Self::Seed::clone_from_slice(slice)
            }

            fn new(key: &Self::Key) -> Self {
                use aes::cipher::KeyInit;
                Self($inner::new(key))
            }
            fn block_encrypt(&self, block: &mut Self::Block) {
                use aes::cipher::BlockEncrypt;
                self.0.encrypt_block(block);
            }
            fn block_encrypt_b2b(&self, block: &Self::Block) -> Self::Block {
                use aes::cipher::BlockEncrypt;
                let mut out_block = Self::Block::default();
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
