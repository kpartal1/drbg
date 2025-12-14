use aes::cipher::{
    ArrayLength,
    consts::{U16, U48},
    generic_array::GenericArray,
};

pub trait Cipher {
    const BLOCK_LEN: usize;
    const KEY_LEN: usize;
    const SEED_LEN: usize = Self::BLOCK_LEN + Self::KEY_LEN;
    const SECURITY_STRENGTH: usize;
    const MIN_ENTROPY: usize = Self::SECURITY_STRENGTH;
    const MAX_ENTROPY: usize = 1 << 35;
    const MAX_PERSONALIZATION_STRING_LENGTH: usize = 1 << 35;
    const MAX_ADDITIONAL_INPUT_LENGTH: usize = 1 << 35;
    const MAX_NUMBER_OF_BITS_PER_REQUEST: u32;

    type Block: AsRef<[u8]> + AsMut<[u8]>;
    type Key: AsRef<[u8]>;

    type SeedLength: ArrayLength<u8>;
    type Seed: AsRef<[u8]>;
    type HalfSecurityStrength: ArrayLength<u8>;
    type Nonce: AsRef<[u8]>;

    fn new(key: &Self::Key) -> Self;
    fn key_from_slice(slice: &[u8]) -> Self::Key;
    fn block_from_slice(slice: &[u8]) -> Self::Block;
    fn seed_from_slice(slice: &[u8]) -> Self::Seed;
    fn nonce_from_slice(slice: &[u8]) -> Self::Nonce;

    fn block_encrypt(&self, block: &mut Self::Block);
    fn block_encrypt_b2b(&self, block: &Self::Block) -> Self::Block;
}

pub struct Aes256(aes::Aes256Enc);

impl Cipher for Aes256 {
    const BLOCK_LEN: usize = 16;
    const KEY_LEN: usize = 32;
    const SECURITY_STRENGTH: usize = Self::KEY_LEN;
    const MAX_NUMBER_OF_BITS_PER_REQUEST: u32 = 1 << 19;

    type Block = aes::Block;
    type Key = aes::cipher::Key<aes::Aes256Enc>;

    type SeedLength = U48;
    type Seed = GenericArray<u8, Self::SeedLength>;
    type HalfSecurityStrength = U16;
    type Nonce = GenericArray<u8, Self::HalfSecurityStrength>;

    fn new(key: &Self::Key) -> Self {
        use aes::cipher::KeyInit;
        Self(aes::Aes256Enc::new(key))
    }
    fn key_from_slice(slice: &[u8]) -> Self::Key {
        Self::Key::clone_from_slice(slice)
    }
    fn block_from_slice(slice: &[u8]) -> Self::Block {
        Self::Block::clone_from_slice(slice)
    }
    fn seed_from_slice(slice: &[u8]) -> Self::Seed {
        Self::Seed::clone_from_slice(slice)
    }
    fn nonce_from_slice(slice: &[u8]) -> Self::Nonce {
        Self::Nonce::clone_from_slice(slice)
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
