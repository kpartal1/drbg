use crate::pr::PredictionResistance;
use std::{fmt::Debug, marker::PhantomData};

pub trait InstantiateInputInit {
    fn init(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self;
}

pub trait ReseedInputInit {
    fn init(entropy_input: &[u8], additional_input: &[u8]) -> Self;
}

pub trait GenerateInputInit {
    fn init(requested_number_of_bits: u32, additional_input: &[u8]) -> Self;
}

pub trait DrbgVariant {
    const MAX_RESEED_INTERVAL: u64;
    const SECURITY_STRENGTH: usize;
    const MIN_ENTROPY: usize = Self::SECURITY_STRENGTH;

    type InstantiateInput: InstantiateInputInit;
    type ReseedInput: ReseedInputInit;
    type GenerateInput: GenerateInputInit;
    type GenerateError: Debug;

    fn instantiate(input: Self::InstantiateInput) -> Self;
    fn reseed(&mut self, input: Self::ReseedInput);
    fn generate(&mut self, input: Self::GenerateInput) -> Result<Vec<u8>, Self::GenerateError>;
}

#[derive(Debug)]
pub struct ReseedRequired;

pub struct Variant<Pr, V> {
    variant: V,
    reseed_counter: u64,
    _pr: PhantomData<Pr>,
}

impl<Pr: PredictionResistance, V: DrbgVariant> DrbgVariant for Variant<Pr, V> {
    const MAX_RESEED_INTERVAL: u64 = V::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = V::SECURITY_STRENGTH;

    type InstantiateInput = V::InstantiateInput;
    type ReseedInput = V::ReseedInput;
    type GenerateInput = V::GenerateInput;
    type GenerateError = ReseedRequired;

    fn instantiate(input: Self::InstantiateInput) -> Self {
        Self {
            variant: V::instantiate(input),
            reseed_counter: 1,
            _pr: PhantomData,
        }
    }
    fn reseed(&mut self, input: Self::ReseedInput) {
        self.variant.reseed(input);
        self.reseed_counter = 1;
    }
    fn generate(&mut self, input: Self::GenerateInput) -> Result<Vec<u8>, Self::GenerateError> {
        if Pr::must_reseed(self.reseed_counter, V::MAX_RESEED_INTERVAL) {
            return Err(ReseedRequired);
        }
        let res = self.variant.generate(input).unwrap();
        self.reseed_counter += 1;
        Ok(res)
    }
}
