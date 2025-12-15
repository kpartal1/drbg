use crate::{
    drbg::variant::{DrbgVariant, GenerateInputInit, InstantiateInputInit, ReseedInputInit},
    hash_based::hashfn::HashFn,
};

pub struct Hash<F: HashFn> {
    v: F::V,
    c: F::C,
}

pub struct HashInstantiateInput {}

impl InstantiateInputInit for HashInstantiateInput {
    fn init(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        todo!()
    }
}

pub struct HashReseedInput {}

impl ReseedInputInit for HashReseedInput {
    fn init(entropy_input: &[u8], additional_input: &[u8]) -> Self {
        todo!()
    }
}

pub struct HashGenerateInput {}

impl GenerateInputInit for HashGenerateInput {
    fn init(requested_number_of_bits: u32, additional_input: &[u8]) -> Self {
        todo!()
    }
}

impl<F: HashFn> DrbgVariant for Hash<F> {
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;
    const SECURITY_STRENGTH: usize = F::SECURITY_STRENGTH;

    type InstantiateInput = HashInstantiateInput;
    type ReseedInput = HashReseedInput;
    type GenerateInput = HashGenerateInput;
    type GenerateError = ();

    fn instantiate(input: Self::InstantiateInput) -> Self {
        todo!()
    }

    fn reseed(&mut self, input: Self::ReseedInput) {
        todo!()
    }

    fn generate(&mut self, input: Self::GenerateInput) -> Result<Vec<u8>, Self::GenerateError> {
        todo!()
    }
}
