use crate::drbg::variant::{DrbgVariant, ReseedRequired};
use cipher::Cipher;

mod cipher;
mod util;

pub use cipher::{Aes128, Aes192, Aes256};

pub struct Ctr<C: Cipher> {
    v: C::Block,
    key: C::Key,
}

impl<C: Cipher> Ctr<C> {
    fn update(&mut self, provided_data: &C::Seed) {
        let cipher = C::new(&self.key);

        let mut temp = C::seed_from_slice(&vec![0; C::SEED_LEN]);
        for block in temp.as_mut().chunks_mut(C::BLOCK_LEN) {
            util::inc(self.v.as_mut());
            let output_block = cipher.block_encrypt_b2b(&self.v);
            block.copy_from_slice(&output_block.as_ref()[..block.len()])
        }

        for (byte, provided_byte) in temp.as_mut().iter_mut().zip(provided_data.as_ref()) {
            *byte ^= provided_byte;
        }

        (self.key, self.v) = C::seed_to_key_block(temp);
    }
}

impl<C: Cipher> DrbgVariant for Ctr<C> {
    const MAX_RESEED_INTERVAL: u64 = C::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = C::SECURITY_STRENGTH;

    fn print_values(&self) {
        println!("key: {:?}", hex::encode(self.key.as_ref()));
        println!("v_block: {:?}", hex::encode(self.v.as_ref()));
    }

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        let seed_material = [entropy_input, nonce, personalization_string].concat();
        let seed_material = util::block_cipher_df::<C>(&seed_material);

        let mut ctr = Self {
            v: C::block_from_slice(&vec![0; C::BLOCK_LEN]),
            key: C::key_from_slice(&vec![0; C::KEY_LEN]),
        };

        ctr.update(&seed_material);

        ctr
    }

    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let seed_material = [entropy_input, additional_input].concat();
        let seed_material = util::block_cipher_df::<C>(&seed_material);
        self.update(&seed_material);
    }

    fn generate(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
        _: u64,
    ) -> Result<(), ReseedRequired> {
        let additional_input = match additional_input.len() {
            0 => C::seed_from_slice(&vec![0; C::SEED_LEN]),
            _ => {
                let additional_input = util::block_cipher_df::<C>(additional_input);
                self.update(&additional_input);
                additional_input
            }
        };

        let cipher = C::new(&self.key);

        for block in bytes.chunks_mut(C::BLOCK_LEN) {
            util::inc(self.v.as_mut());
            let output_block = cipher.block_encrypt_b2b(&self.v);
            block.copy_from_slice(&output_block.as_ref()[..block.len()]);
        }

        self.update(&additional_input);

        Ok(())
    }
}
