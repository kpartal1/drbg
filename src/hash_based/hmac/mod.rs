use crate::{
    drbg::variant::{DrbgVariant, GenerateInputInit, InstantiateInputInit, ReseedInputInit},
    hash_based::hashfn::HashFn,
};

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

pub struct HmacInstantiateInput<F: HashFn> {
    entropy_input: F::Entropy,
    nonce: F::Nonce,
    personalizaton_string: Vec<u8>,
}

impl<F: HashFn> InstantiateInputInit for HmacInstantiateInput<F> {
    fn init(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        Self {
            entropy_input: F::entropy_from_slice(entropy_input),
            nonce: F::nonce_from_slice(nonce),
            personalizaton_string: Vec::from(personalization_string),
        }
    }
}

pub struct HmacReseedInput<F: HashFn> {
    entropy_input: F::Entropy,
    additional_input: Vec<u8>,
}

impl<F: HashFn> ReseedInputInit for HmacReseedInput<F> {
    fn init(entropy_input: &[u8], additional_input: &[u8]) -> Self {
        Self {
            entropy_input: F::entropy_from_slice(entropy_input),
            additional_input: Vec::from(additional_input),
        }
    }
}

pub struct HmacGenerateInput {
    requested_number_of_bytes: usize,
    additional_input: Vec<u8>,
}

impl GenerateInputInit for HmacGenerateInput {
    fn init(requested_number_of_bytes: usize, additional_input: &[u8], _: u64) -> Self {
        Self {
            requested_number_of_bytes,
            additional_input: Vec::from(additional_input),
        }
    }
}

impl<F: HashFn> DrbgVariant for Hmac<F> {
    const MAX_RESEED_INTERVAL: u64 = F::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = F::SECURITY_STRENGTH;

    type InstantiateInput = HmacInstantiateInput<F>;
    type ReseedInput = HmacReseedInput<F>;
    type GenerateInput = HmacGenerateInput;
    type GenerateError = std::convert::Infallible;

    fn instantiate(
        HmacInstantiateInput {
            entropy_input,
            nonce,
            personalizaton_string,
        }: Self::InstantiateInput,
    ) -> Self {
        let mut seed_material = Vec::with_capacity(
            entropy_input.as_ref().len() + nonce.as_ref().len() + personalizaton_string.len(),
        );
        seed_material.extend(entropy_input.as_ref());
        seed_material.extend(nonce.as_ref());
        seed_material.extend(personalizaton_string);
        let mut hmac = Self {
            v: F::hash_from_slice(&vec![0x01; F::BLOCK_LEN]),
            key: F::hash_from_slice(&vec![0x00; F::BLOCK_LEN]),
        };
        hmac.update(&seed_material);
        hmac
    }

    fn reseed(
        &mut self,
        HmacReseedInput {
            entropy_input,
            additional_input,
        }: Self::ReseedInput,
    ) {
        let mut seed_material =
            Vec::with_capacity(entropy_input.as_ref().len() + additional_input.len());
        seed_material.extend(entropy_input.as_ref());
        seed_material.extend(additional_input);
        self.update(&seed_material);
    }

    fn generate(
        &mut self,
        HmacGenerateInput {
            requested_number_of_bytes,
            additional_input,
        }: Self::GenerateInput,
    ) -> Result<Vec<u8>, Self::GenerateError> {
        if !additional_input.is_empty() {
            self.update(&additional_input);
        }
        let mut temp = Vec::with_capacity(requested_number_of_bytes);
        while temp.len() < requested_number_of_bytes {
            self.v = F::hmac(&self.key, self.v.as_ref());
            temp.extend(self.v.as_ref());
        }
        self.update(&additional_input);
        Ok(Vec::from(&temp[..requested_number_of_bytes]))
    }
}
