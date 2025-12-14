use aes::cipher::{
    consts::{U8, U12, U16, U32, U40, U48},
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
    type Key;

    type Seed: AsRef<[u8]>;
    type Nonce;

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

    type Seed = GenericArray<u8, U48>;
    type Nonce = GenericArray<u8, U16>;

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

pub struct Aes192(aes::Aes192Enc);

impl Cipher for Aes192 {
    const BLOCK_LEN: usize = 16;
    const KEY_LEN: usize = 24;
    const SECURITY_STRENGTH: usize = Self::KEY_LEN;
    const MAX_NUMBER_OF_BITS_PER_REQUEST: u32 = 1 << 19;

    type Block = aes::Block;
    type Key = aes::cipher::Key<aes::Aes192Enc>;

    type Seed = GenericArray<u8, U40>;
    type Nonce = GenericArray<u8, U12>;

    fn new(key: &Self::Key) -> Self {
        use aes::cipher::KeyInit;
        Self(aes::Aes192Enc::new(key))
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

pub struct Aes128(aes::Aes128Enc);

impl Cipher for Aes128 {
    const BLOCK_LEN: usize = 16;
    const KEY_LEN: usize = 16;
    const SECURITY_STRENGTH: usize = Self::KEY_LEN;
    const MAX_NUMBER_OF_BITS_PER_REQUEST: u32 = 1 << 19;

    type Block = aes::Block;
    type Key = aes::cipher::Key<aes::Aes128Enc>;

    type Seed = GenericArray<u8, U32>;
    type Nonce = GenericArray<u8, U8>;

    fn new(key: &Self::Key) -> Self {
        use aes::cipher::KeyInit;
        Self(aes::Aes128Enc::new(key))
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

// I have no idea how to do macros :(
// macro_rules! impl_aes {
//     ($cipher:ident, $inner:ident, $block_len:literal, $key_len:literal, $security_strength:literal, $max_number_of_bits_per_request:literal, $block:ident, $key:ident, $seed:ident, $nonce:ident) => {
//         pub struct $cipher($inner);

//         impl Cipher for $cipher {
//             const BLOCK_LEN: usize = $block_len;
//             const KEY_LEN: usize = $key_len;
//             const SECURITY_STRENGTH: usize = $security_strength
//             const MAX_NUMBER_OF_BITS_PER_REQUEST: u32 = $max_number_of_bits_per_request;

//             type Block = $block;
//             type Key = $key;

//             type Seed = $seed;
//             type Nonce = $nonce;

//             fn new(key: &Self::Key) -> Self {
//                 use aes::cipher::KeyInit;
//                 Self($inner::new(key))
//             }
//             fn key_from_slice(slice: &[u8]) -> Self::Key {
//                 Self::Key::clone_from_slice(slice)
//             }
//             fn block_from_slice(slice: &[u8]) -> Self::Block {
//                 Self::Block::clone_from_slice(slice)
//             }
//             fn seed_from_slice(slice: &[u8]) -> Self::Seed {
//                 Self::Seed::clone_from_slice(slice)
//             }
//             fn nonce_from_slice(slice: &[u8]) -> Self::Nonce {
//                 Self::Nonce::clone_from_slice(slice)
//             }

//             fn block_encrypt(&self, block: &mut Self::Block) {
//                 use aes::cipher::BlockEncrypt;
//                 self.0.encrypt_block(block);
//             }
//             fn block_encrypt_b2b(&self, block: &Self::Block) -> Self::Block {
//                 use aes::cipher::BlockEncrypt;
//                 let mut out_block = Self::Block::default();
//                 self.0.encrypt_block_b2b(block, &mut out_block);
//                 out_block
//             }
//         }
//     };
// }
