use crate::drbg::variant::DrbgVariant;
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

impl<C: Cipher> DrbgVariant for Ctr<C> {
    const MAX_RESEED_INTERVAL: u64 = C::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = C::SECURITY_STRENGTH;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
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

    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let mut seed_material = Vec::with_capacity(entropy_input.len() + additional_input.len());
        seed_material.extend(entropy_input);
        seed_material.extend(additional_input);
        let seed_material = util::block_cipher_df::<C>(&seed_material);
        self.update(&seed_material);
    }

    type GenerateError = std::convert::Infallible;
    fn generate(
        &mut self,
        buf: &mut [u8],
        additional_input: &[u8],
        _: u64,
    ) -> Result<(), Self::GenerateError> {
        let additional_input = match additional_input.len() {
            0 => C::seed_from_slice(&vec![0; C::SEED_LEN]),
            _ => {
                let additional_input = util::block_cipher_df::<C>(additional_input);
                self.update(&additional_input);
                additional_input
            }
        };

        let cipher = C::new(&self.key);

        for block in buf.chunks_mut(self.v.as_ref().len()) {
            util::inc(self.v.as_mut());
            let output_block = cipher.block_encrypt_b2b(&self.v);
            block.copy_from_slice(output_block.as_ref());
        }

        // let mut temp: Vec<u8> = Vec::with_capacity(buf.len());
        // while temp.len() < buf.len() {
        //     util::inc(self.v.as_mut());
        //     let output_block = cipher.block_encrypt_b2b(&self.v);
        //     temp.extend(output_block.as_ref());
        // }

        self.update(&additional_input);

        Ok(())
    }
}
