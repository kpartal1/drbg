use crate::{drbg::variant::DrbgVariant, hash_based::hashfn::HashFn};

pub struct Hmac<F: HashFn> {
    v: F::Hash,
    key: F::Hash,
}

impl<F: HashFn> Hmac<F> {
    fn update(&mut self, provided_data: &[u8]) {
        let mut input = Vec::with_capacity(
            self.v.as_ref().len() + std::mem::size_of::<u8>() + provided_data.len(),
        );
        input.extend(self.v.as_ref());
        input.push(0x00);
        input.extend(provided_data);
        self.key = F::hmac(&self.key, &input);
        self.v = F::hmac(&self.key, self.v.as_ref());

        if !provided_data.is_empty() {
            let mut input = Vec::with_capacity(
                self.v.as_ref().len() + std::mem::size_of::<u8>() + provided_data.len(),
            );
            input.extend(self.v.as_ref());
            input.push(0x01);
            input.extend(provided_data);
            self.key = F::hmac(&self.key, &input);
            self.v = F::hmac(&self.key, self.v.as_ref());
        }
    }
}

impl<F: HashFn> DrbgVariant for Hmac<F> {
    const MAX_RESEED_INTERVAL: u64 = F::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = F::SECURITY_STRENGTH;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        let mut seed_material =
            Vec::with_capacity(entropy_input.len() + nonce.len() + personalization_string.len());
        seed_material.extend(entropy_input);
        seed_material.extend(nonce);
        seed_material.extend(personalization_string);
        let mut hmac = Self {
            v: F::hash_from_slice(&vec![0x01; F::BLOCK_LEN]),
            key: F::hash_from_slice(&vec![0x00; F::BLOCK_LEN]),
        };
        hmac.update(&seed_material);
        hmac
    }

    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let mut seed_material = Vec::with_capacity(entropy_input.len() + additional_input.len());
        seed_material.extend(entropy_input);
        seed_material.extend(additional_input);
        self.update(&seed_material);
    }

    type GenerateError = std::convert::Infallible;
    fn generate(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
        _: u64,
    ) -> Result<(), Self::GenerateError> {
        if !additional_input.is_empty() {
            self.update(additional_input);
        }
        let mut temp: Vec<u8> = Vec::with_capacity(bytes.len());
        while temp.len() < bytes.len() {
            self.v = F::hmac(&self.key, self.v.as_ref());
            temp.extend(self.v.as_ref());
        }
        self.update(additional_input);
        // Ok(Vec::from(&temp[..buf.len()]))
        Ok(())
    }
}
