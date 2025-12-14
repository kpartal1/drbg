// use aes::{
//     Aes256Enc, Block,
//     cipher::{
//         BlockEncrypt, KeyInit,
//         consts::{U16, U32, U48},
//         generic_array::GenericArray,
//     },
// };
// use rand::TryRngCore;
// use rand::rngs::OsRng;

// const BLOCKLEN: usize = 16;
// const KEYLEN: usize = 32;
// const SEEDLEN: usize = BLOCKLEN + KEYLEN;
// const MAX_RESEED_INTERVAL: u64 = 1 << 48;

// type Seed = GenericArray<u8, U48>;
// type Nonce = GenericArray<u8, U16>;
// type Key = GenericArray<u8, U32>;

// const DF_BLOCKLEN: usize = 16;
// const DF_KEYLEN: usize = 32;
// const DF_OUTLEN: usize = DF_BLOCKLEN + DF_KEYLEN;

// fn block_cipher_df(input_string: &[u8]) -> Seed {
//     debug_assert!(input_string.len().is_multiple_of(8));
//     let l = (input_string.len() / 8) as u32;
//     let n = (DF_OUTLEN / 8) as u32;
//     let mut s = Vec::with_capacity(std::mem::size_of::<u32>() * 2 + input_string.len() + 1);
//     s.extend(l.to_be_bytes());
//     s.extend(n.to_be_bytes());
//     s.extend(input_string);
//     s.push(0x80);
//     while !s.len().is_multiple_of(DF_BLOCKLEN) {
//         s.push(0);
//     }

//     let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
//               \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
//     let k = Key::from_slice(&k[..DF_KEYLEN]);

//     let mut temp = Vec::with_capacity(DF_OUTLEN);
//     let mut i = 0u32;
//     while temp.len() < KEYLEN + DF_OUTLEN {
//         let iv_s = {
//             let mut v = Vec::with_capacity(
//                 std::mem::size_of::<u32>() + DF_OUTLEN - std::mem::size_of::<u32>(),
//             );
//             v.extend(i.to_be_bytes());
//             v.extend([0; DF_OUTLEN - std::mem::size_of::<u32>()]);
//             v.extend(s.clone());
//             v
//         };
//         temp.extend(bcc(k, &iv_s));
//         i += 1;
//     }

//     let k = Key::from_slice(&temp[..DF_KEYLEN]);

//     let cipher = Aes256Enc::new(k);

//     let x = Block::from_mut_slice(&mut temp[DF_KEYLEN..DF_OUTLEN]);
//     let mut temp = Vec::with_capacity(DF_OUTLEN);
//     while temp.len() < DF_OUTLEN {
//         cipher.encrypt_block(x);
//         temp.extend(*x);
//     }

//     Seed::clone_from_slice(&temp[..DF_OUTLEN])
// }

// fn bcc(key: &Key, data: &[u8]) -> Block {
//     let cipher = Aes256Enc::new(key);

//     let chaining_value = GenericArray::from([0u8; DF_BLOCKLEN]);
//     for block in data.chunks(DF_BLOCKLEN) {
//         let mut chaining_value =
//             GenericArray::from_iter(chaining_value.into_iter().zip(block).map(|(i, j)| i ^ j));
//         cipher.encrypt_block(&mut chaining_value);
//     }
//     Block::from(chaining_value)
// }

// struct DrbgNoPrCtrAes256 {
//     v: Block,
//     key: Key,
//     reseed_counter: u64,
//     reseed_interval: u64,
// }

// struct DrbgNoPrCtrAes256Error;

// fn inc(block: &mut [u8]) {
//     for byte in block.iter_mut().rev() {
//         *byte = byte.wrapping_add(1);
//         if *byte != 0 {
//             break;
//         }
//     }
// }

// impl DrbgNoPrCtrAes256 {
//     fn update(&mut self, provided_data: Seed) {
//         let cipher = Aes256Enc::new(&self.key);

//         let mut blocks = Vec::with_capacity(SEEDLEN);
//         while blocks.len() < SEEDLEN {
//             inc(&mut self.v);
//             let mut output_block = self.v;
//             cipher.encrypt_block(&mut output_block);
//             blocks.extend(output_block);
//         }
//         // cipher.encrypt_blocks(&mut blocks);

//         println!("{blocks:?}");

//         let temp = blocks
//             .into_iter()
//             // .flatten()
//             .zip(provided_data)
//             .map(|(i, j)| i ^ j)
//             .collect::<Vec<u8>>();

//         self.key = GenericArray::clone_from_slice(&temp[..KEYLEN]);
//         self.v = GenericArray::clone_from_slice(&temp[temp.len() - BLOCKLEN..]);
//     }

//     fn instantiate(entropy_input: Seed, nonce: Nonce, personalization_string: &[u8]) -> Self {
//         let seed_material = {
//             let mut v = Vec::with_capacity(
//                 entropy_input.len() + nonce.len() + personalization_string.len(),
//             );
//             v.extend(entropy_input);
//             v.extend(nonce);
//             v.extend(personalization_string);
//             v
//         };
//         let seed_material = block_cipher_df(&seed_material);

//         let mut ret = Self {
//             v: Block::from([0; BLOCKLEN]),
//             key: Key::from([0; KEYLEN]),
//             reseed_counter: 1,
//             reseed_interval: 10,
//         };

//         ret.update(seed_material);

//         ret
//     }

//     pub fn reseed(&mut self, entropy_input: Seed, additional_input: &[u8]) {
//         let mut seed_material = Vec::with_capacity(entropy_input.len() + additional_input.len());
//         seed_material.extend(entropy_input);
//         seed_material.extend(additional_input);
//         let seed_material = block_cipher_df(&seed_material);
//         self.update(seed_material);
//         self.reseed_counter = 1;
//     }

//     fn generate(&mut self, additional_input: &[u8]) -> Result<Block, &'static str> {
//         if self.reseed_counter > self.reseed_interval {
//             return Err("DRBG must be reseeded.");
//         }

//         let additional_input = match additional_input.len() {
//             0 => Seed::from([0; SEEDLEN]),
//             _ => {
//                 let additional_input = block_cipher_df(additional_input);
//                 self.update(additional_input);
//                 additional_input
//             }
//         };

//         let cipher = Aes256Enc::new(&self.key);

//         let mut temp = Vec::with_capacity(SEEDLEN.div_ceil(BLOCKLEN));
//         while temp.len() * BLOCKLEN < SEEDLEN {
//             inc(&mut self.v);
//             temp.push(self.v);
//         }
//         cipher.encrypt_blocks(&mut temp);

//         self.update(additional_input);
//         self.reseed_counter += 1;

//         Ok(Block::from_iter(temp.into_iter().flatten().take(BLOCKLEN)))
//     }
// }

use drbg::DrbgNoPrCtrAes256;
use rand::{TryRngCore, rngs::OsRng};

fn main() {
    let mut seed = [0; 48];
    OsRng
        .try_fill_bytes(&mut seed)
        .expect("Failed to generate entropy for seed.");
    let mut nonce = [0; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .expect("Failed to generate entropy for nonce.");
    let mut drbg = DrbgNoPrCtrAes256::try_get_random_bytes(10, None);

    // for _ in 0..100 {
    //     match drbg.generate(&[]) {
    //         Ok(random) => println!("{random:?}"),
    //         Err(_) => {
    //             let mut entropy_input = Seed::from([0; 48]);
    //             OsRng
    //                 .try_fill_bytes(&mut entropy_input)
    //                 .expect("Failed to generate entropy for seed.");
    //             drbg.reseed(entropy_input, &[]);
    //         }
    //     }
    // }
}
