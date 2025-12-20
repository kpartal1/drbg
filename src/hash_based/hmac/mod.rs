use crate::{
    drbg::variant::{DrbgVariant, ReseedRequired},
    hash_based::hashfn::HashFn,
};

pub struct Hmac<F: HashFn> {
    v: F::Hash,
    key: F::Hash,
}

impl<F: HashFn> Hmac<F> {
    fn update(&mut self, provided_data: &[u8]) {
        let input = [self.v.as_ref(), &[0x00], provided_data].concat();
        self.key = F::hmac(&self.key, &input);
        self.v = F::hmac(&self.key, self.v.as_ref());

        if !provided_data.is_empty() {
            let input = [self.v.as_ref(), &[0x01], provided_data].concat();
            self.key = F::hmac(&self.key, &input);
            self.v = F::hmac(&self.key, self.v.as_ref());
        }
    }
}

impl<F: HashFn> DrbgVariant for Hmac<F> {
    const MAX_RESEED_INTERVAL: u64 = F::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = F::SECURITY_STRENGTH;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        let seed_material = [entropy_input, nonce, personalization_string].concat();
        let mut hmac = Self {
            v: F::hash_from_slice(&vec![0x01; F::BLOCK_LEN]),
            key: F::hash_from_slice(&vec![0x00; F::BLOCK_LEN]),
        };
        hmac.update(&seed_material);
        hmac
    }

    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let seed_material = [entropy_input, additional_input].concat();
        self.update(&seed_material);
    }

    fn generate(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
        _: u64,
    ) -> Result<(), ReseedRequired> {
        if !additional_input.is_empty() {
            self.update(additional_input);
        }
        for block in bytes.chunks_mut(F::BLOCK_LEN) {
            self.v = F::hmac(&self.key, self.v.as_ref());
            block.copy_from_slice(&self.v.as_ref()[..block.len()]);
        }
        self.update(additional_input);

        Ok(())
    }
}
