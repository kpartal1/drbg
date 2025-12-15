use crate::drbg::variant::{DrbgVariant, GenerateInputInit, InstantiateInputInit, ReseedInputInit};
use cipher::Cipher;

mod cipher;
mod util;

pub use cipher::{Aes128, Aes192, Aes256};

pub struct Ctr<C: Cipher> {
    v: C::Block,
    key: C::Key,
}

impl<C: Cipher> Ctr<C> {
    pub fn update(&mut self, provided_data: &C::Seed) {
        let cipher = C::new(&self.key);

        let mut blocks: Vec<u8> = Vec::with_capacity(C::SEED_LEN);
        while blocks.len() < C::SEED_LEN {
            util::inc(self.v.as_mut());
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

#[derive(Debug)]
pub struct RequestedTooManyBytes;

pub struct CtrInstantiateInput<C: Cipher> {
    entropy_input: C::Key,
    nonce: C::Nonce,
    personalization_string: Vec<u8>,
}

impl<C: Cipher> InstantiateInputInit for CtrInstantiateInput<C> {
    fn init(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        Self {
            entropy_input: C::key_from_slice(entropy_input),
            nonce: C::nonce_from_slice(nonce),
            personalization_string: Vec::from(personalization_string),
        }
    }
}

pub struct CtrReseedInput<C: Cipher> {
    entropy_input: C::Key,
    additional_input: Vec<u8>,
}

impl<C: Cipher> ReseedInputInit for CtrReseedInput<C> {
    fn init(entropy_input: &[u8], additional_input: &[u8]) -> Self {
        Self {
            entropy_input: C::key_from_slice(entropy_input),
            additional_input: Vec::from(additional_input),
        }
    }
}

pub struct CtrGenerateInput {
    requested_number_of_bytes: u32,
    additional_input: Vec<u8>,
}

impl GenerateInputInit for CtrGenerateInput {
    fn init(requested_number_of_bytes: u32, additional_input: &[u8]) -> Self {
        Self {
            requested_number_of_bytes,
            additional_input: Vec::from(additional_input),
        }
    }
}

impl<C: Cipher> DrbgVariant for Ctr<C> {
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;
    const SECURITY_STRENGTH: usize = C::SECURITY_STRENGTH;

    type InstantiateInput = CtrInstantiateInput<cipher::Aes256>;
    type ReseedInput = CtrReseedInput<cipher::Aes256>;
    type GenerateInput = CtrGenerateInput;
    type GenerateError = RequestedTooManyBytes;

    fn instantiate(
        CtrInstantiateInput {
            entropy_input,
            nonce,
            personalization_string,
        }: Self::InstantiateInput,
    ) -> Self {
        let mut seed_material =
            Vec::with_capacity(entropy_input.len() + nonce.len() + personalization_string.len());
        seed_material.extend(entropy_input);
        seed_material.extend(nonce);
        seed_material.extend(personalization_string);

        let seed_material = util::block_cipher_df::<C>(&seed_material);

        let mut ret = Self {
            v: C::block_from_slice(&vec![0; C::BLOCK_LEN]),
            key: C::key_from_slice(&vec![0; C::KEY_LEN]),
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
        let seed_material = util::block_cipher_df::<C>(&seed_material);
        self.update(&seed_material);
    }

    fn generate(
        &mut self,
        CtrGenerateInput {
            requested_number_of_bytes,
            additional_input,
        }: Self::GenerateInput,
    ) -> Result<Vec<u8>, Self::GenerateError> {
        if requested_number_of_bytes > C::MAX_NUMBER_OF_BYTES_PER_REQUEST {
            return Err(RequestedTooManyBytes);
        }
        let requested_number_of_bytes = requested_number_of_bytes as usize;

        let additional_input = match additional_input.len() {
            0 => C::seed_from_slice(&vec![0; C::SEED_LEN]),
            _ => {
                let additional_input = util::block_cipher_df::<C>(&additional_input);
                self.update(&additional_input);
                additional_input
            }
        };

        let cipher = C::new(&self.key);

        let mut temp: Vec<u8> = Vec::with_capacity(C::SEED_LEN.div_ceil(C::BLOCK_LEN));
        while temp.len() < requested_number_of_bytes {
            util::inc(self.v.as_mut());
            let output_block = cipher.block_encrypt_b2b(&self.v);
            temp.extend(output_block.as_ref());
        }

        self.update(&additional_input);

        Ok(Vec::from(&temp[..requested_number_of_bytes]))
    }
}
