use std::fmt::Debug;

pub trait InstantiateInputInit {
    fn init(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self;
}

pub trait ReseedInputInit {
    fn init(entropy_input: &[u8], additional_input: &[u8]) -> Self;
}

pub trait GenerateInputInit<'a> {
    fn init(buf: &'a mut [u8], additional_input: &'a [u8], reseed_counter: u64) -> Self;
}

pub trait DrbgVariant<'a> {
    const MAX_RESEED_INTERVAL: u64;
    const SECURITY_STRENGTH: usize;

    const MIN_ENTROPY: usize = Self::SECURITY_STRENGTH;
    const MAX_ENTROPY: usize = 1 << 35;
    const MAX_PERSONALIZATION_STRING_LENGTH: usize = 1 << 35;
    const MAX_ADDITIONAL_INPUT_LENGTH: usize = 1 << 35;

    type InstantiateInput: InstantiateInputInit;
    type ReseedInput: ReseedInputInit;
    type GenerateInput: GenerateInputInit<'a>;
    type GenerateError: Debug;

    fn instantiate(input: Self::InstantiateInput) -> Self;
    fn reseed(&mut self, input: Self::ReseedInput);
    fn generate(&mut self, input: &mut Self::GenerateInput) -> Result<(), Self::GenerateError>;
}
