use std::fmt::Debug;

pub trait DrbgVariant {
    const MAX_RESEED_INTERVAL: u64;
    const SECURITY_STRENGTH: usize;

    const MIN_ENTROPY: usize = Self::SECURITY_STRENGTH;
    const MAX_ENTROPY: usize = 1 << 35;
    const MAX_PERSONALIZATION_STRING_LENGTH: usize = 1 << 35;
    const MAX_ADDITIONAL_INPUT_LENGTH: usize = 1 << 35;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self;
    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]);
    type GenerateError: Debug;
    fn generate(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
        reseed_counter: u64,
    ) -> Result<(), Self::GenerateError>;
}
