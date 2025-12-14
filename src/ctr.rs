use std::marker::PhantomData;

pub mod cipher;

use cipher::Cipher;

use crate::{
    drbg::{DrbgVariant, GenerateInputInit, InstantiateInputInit, ReseedInputInit},
    pr::PredictionResistance,
};

pub struct Ctr<Pr, C: Cipher> {
    v: C::Block,
    key: C::Key,
    reseed_counter: u64,
    _pr: PhantomData<Pr>,
}

fn block_cipher_df<C: Cipher>(input_string: &[u8]) -> C::Seed {
    debug_assert!(input_string.len().is_multiple_of(8));
    let l = (input_string.len() / 8) as u32;
    let n = (C::SEED_LEN / 8) as u32;

    let mut s = Vec::with_capacity(std::mem::size_of::<u32>() * 2 + input_string.len() + 1);
    s.extend(l.to_be_bytes());
    s.extend(n.to_be_bytes());
    s.extend(input_string);
    s.push(0x80);
    while !s.len().is_multiple_of(C::BLOCK_LEN) {
        s.push(0);
    }

    let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
              \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    let k = C::key_from_slice(&k[..C::KEY_LEN]);

    let mut temp = Vec::with_capacity(C::SEED_LEN);
    let mut i = 0u32;
    while temp.len() < C::KEY_LEN + C::SEED_LEN {
        let mut iv_s = Vec::with_capacity(C::SEED_LEN + s.len());
        iv_s.extend(i.to_be_bytes());
        iv_s.extend(vec![0; C::SEED_LEN - std::mem::size_of::<u32>()]);
        iv_s.extend(s.clone());

        let bcc_out: C::Block = bcc::<C>(&k, &iv_s);
        temp.extend(bcc_out.as_ref());
        i += 1;
    }

    let k = &temp[..C::KEY_LEN];
    let cipher = C::new(&C::key_from_slice(k));

    let mut x = C::block_from_slice(&temp[C::KEY_LEN..C::SEED_LEN]);
    let mut temp = Vec::with_capacity(C::SEED_LEN);
    while temp.len() < C::SEED_LEN {
        cipher.block_encrypt(&mut x);
        temp.extend(x.as_ref());
    }

    C::seed_from_slice(&temp[..C::SEED_LEN])
}

fn bcc<C: Cipher>(key: &C::Key, data: &[u8]) -> C::Block {
    let cipher = C::new(key);

    let mut chaining_value = C::block_from_slice(&vec![0; C::BLOCK_LEN]);
    for block in data.chunks(C::BLOCK_LEN) {
        for (i, &b) in block.iter().enumerate() {
            chaining_value.as_mut()[i] ^= b;
        }

        cipher.block_encrypt(&mut chaining_value);
    }

    chaining_value
}

fn inc(block: &mut [u8]) {
    for byte in block.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

impl<Pr, C: Cipher> Ctr<Pr, C> {
    fn update(&mut self, provided_data: &C::Seed) {
        let cipher = C::new(&self.key);

        let mut blocks: Vec<u8> = Vec::with_capacity(C::SEED_LEN);
        while blocks.len() < C::SEED_LEN {
            inc(self.v.as_mut());
            let output_block = cipher.block_encrypt_b2b(&self.v);
            blocks.extend(output_block.as_ref());
        }

        let temp = blocks
            .into_iter()
            .zip(provided_data.as_ref())
            .map(|(i, j)| i ^ j)
            .collect::<Vec<u8>>();

        self.key = C::key_from_slice(&temp[..C::KEY_LEN]);
        self.v = C::block_from_slice(&temp[temp.len() - C::BLOCK_LEN..]);
    }
}

pub struct CtrInstantiateInput<C: Cipher> {
    entropy_input: C::Key,
    nonce: C::Nonce,
    personalization_string: Vec<u8>,
}

impl<C: Cipher> InstantiateInputInit for CtrInstantiateInput<C> {
    fn init(personalization_string: Option<&[u8]>) -> Self {
        Self {
            entropy_input: C::key_from_slice(&vec![0; C::KEY_LEN]),
            nonce: C::nonce_from_slice(&vec![0; C::SECURITY_STRENGTH / 2]),
            personalization_string: personalization_string.map_or(vec![], |v| v.to_vec()),
        }
    }
}

pub struct CtrReseedInput<C: Cipher> {
    entropy_input: C::Key,
    additional_input: Vec<u8>,
}

impl<C: Cipher> ReseedInputInit for CtrReseedInput<C> {
    fn init() -> Self {
        todo!()
    }
}

pub struct CtrGenerateInput {
    requested_number_of_bits: u32,
    additional_input: Vec<u8>,
}

impl GenerateInputInit for CtrGenerateInput {
    fn init() -> Self {
        todo!()
    }
}

impl<Pr: PredictionResistance, C: Cipher> DrbgVariant for Ctr<Pr, C> {
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;
    type WorkingState = Self;
    type InstantiateInput = CtrInstantiateInput<cipher::Aes256>;
    type ReseedInput = CtrReseedInput<cipher::Aes256>;
    type GenerateInput = CtrGenerateInput;
    type GenerateOutput = Vec<u8>;
    fn instantiate(
        CtrInstantiateInput {
            entropy_input,
            nonce,
            personalization_string,
        }: Self::InstantiateInput,
    ) -> Self {
        let seed_material = {
            let mut v = Vec::with_capacity(
                entropy_input.len() + nonce.len() + personalization_string.len(),
            );
            v.extend(entropy_input);
            v.extend(nonce);
            v.extend(personalization_string);
            v
        };
        let seed_material = block_cipher_df::<C>(&seed_material);

        let mut ret = Self {
            v: C::block_from_slice(&vec![0; C::BLOCK_LEN]),
            key: C::key_from_slice(&vec![0; C::KEY_LEN]),
            reseed_counter: 1,
            _pr: PhantomData,
        };

        ret.update(&seed_material);

        ret
    }
    fn reseed(
        &mut self,
        CtrReseedInput {
            entropy_input,
            additional_input,
        }: Self::ReseedInput,
    ) {
        let mut seed_material = Vec::with_capacity(entropy_input.len() + additional_input.len());
        seed_material.extend(entropy_input);
        seed_material.extend(additional_input);
        let seed_material = block_cipher_df::<C>(&seed_material);
        self.update(&seed_material);
        self.reseed_counter = 1;
    }
    fn generate(
        &mut self,
        CtrGenerateInput {
            requested_number_of_bits,
            additional_input,
        }: Self::GenerateInput,
    ) -> Result<Self::GenerateOutput, crate::drbg::GenerateError> {
        if Pr::must_reseed(self.reseed_counter, Self::MAX_RESEED_INTERVAL) {
            return Err(crate::drbg::GenerateError::ReseedRequired);
        }

        let requested_number_of_bits =
            requested_number_of_bits.min(C::MAX_NUMBER_OF_BITS_PER_REQUEST) as usize;

        let additional_input = match additional_input.len() {
            0 => C::seed_from_slice(&vec![0; C::SEED_LEN]),
            _ => {
                let additional_input = block_cipher_df::<C>(&additional_input);
                self.update(&additional_input);
                additional_input
            }
        };

        let cipher = C::new(&self.key);

        let mut temp: Vec<u8> = Vec::with_capacity(C::SEED_LEN.div_ceil(C::BLOCK_LEN));
        while temp.len() < requested_number_of_bits {
            inc(self.v.as_mut());
            let output_block = cipher.block_encrypt_b2b(&self.v);
            temp.extend(output_block.as_ref());
        }

        self.update(&additional_input);
        self.reseed_counter += 1;

        Ok(temp
            .into_iter()
            .take(requested_number_of_bits)
            .collect::<Vec<_>>())
    }
}
