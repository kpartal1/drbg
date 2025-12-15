use crate::drbg::variant::{DrbgVariant, GenerateInputInit, InstantiateInputInit, ReseedInputInit};
use entropy::Entropy;
use std::marker::PhantomData;

pub mod entropy;
pub mod variant;

pub struct Drbg<V, E> {
    variant: V,
    _entropy: PhantomData<E>,
}

impl<V: DrbgVariant, E> DrbgVariant for Drbg<V, E> {
    const MAX_RESEED_INTERVAL: u64 = V::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = V::SECURITY_STRENGTH;

    type InstantiateInput = V::InstantiateInput;
    type ReseedInput = V::ReseedInput;
    type GenerateInput = V::GenerateInput;
    type GenerateError = <V as DrbgVariant>::GenerateError;

    fn instantiate(input: Self::InstantiateInput) -> Self {
        Self {
            variant: V::instantiate(input),
            _entropy: PhantomData,
        }
    }
    fn reseed(&mut self, input: Self::ReseedInput) {
        self.variant.reseed(input);
    }
    fn generate(&mut self, input: Self::GenerateInput) -> Result<Vec<u8>, Self::GenerateError> {
        self.variant.generate(input)
    }
}

#[derive(Debug)]
pub enum DrbgError<V, E> {
    GenerateError(V),
    EntropyError(E),
}

impl<V: DrbgVariant, E: Entropy> Drbg<V, E> {
    pub fn new(personalization_string: Vec<u8>) -> Result<Self, E::Error> {
        let mut entropy_input = vec![0; V::MIN_ENTROPY];
        E::try_fill_bytes(&mut entropy_input)?;
        let mut nonce = vec![0; V::SECURITY_STRENGTH / 2];
        E::try_fill_bytes(&mut nonce)?;
        let ii = <V as DrbgVariant>::InstantiateInput::init(
            &entropy_input,
            &nonce,
            &personalization_string,
        );
        let variant = <V as DrbgVariant>::instantiate(ii);
        Ok(Self {
            variant,
            _entropy: PhantomData,
        })
    }

    pub fn get_random_bytes(
        &mut self,
        requested_number_of_bytes: u32,
        additional_input: Vec<u8>,
    ) -> Result<Vec<u8>, DrbgError<V::GenerateError, E::Error>> {
        let gi =
            <V as DrbgVariant>::GenerateInput::init(requested_number_of_bytes, &additional_input);
        match self.variant.generate(gi) {
            Ok(block) => Ok(block),
            Err(_) => {
                let mut entropy_input = vec![0; V::MIN_ENTROPY];
                E::try_fill_bytes(&mut entropy_input).map_err(DrbgError::EntropyError)?;
                let ri = <V as DrbgVariant>::ReseedInput::init(&entropy_input, &additional_input);
                self.variant.reseed(ri);
                let gi = <V as DrbgVariant>::GenerateInput::init(
                    requested_number_of_bytes,
                    &additional_input,
                );
                Ok(self
                    .variant
                    .generate(gi)
                    .map_err(DrbgError::GenerateError)?)
            }
        }
    }

    pub fn random_bytes(
        requested_number_of_bytes: u32,
        personalization_string: Vec<u8>,
        additional_input: Vec<u8>,
    ) -> Result<Vec<u8>, DrbgError<V::GenerateError, E::Error>> {
        let mut entropy_input = vec![0; V::MIN_ENTROPY];
        E::try_fill_bytes(&mut entropy_input).map_err(DrbgError::EntropyError)?;
        let mut nonce = vec![0; V::SECURITY_STRENGTH / 2];
        E::try_fill_bytes(&mut nonce).map_err(DrbgError::EntropyError)?;
        let ii = <V as DrbgVariant>::InstantiateInput::init(
            &entropy_input,
            &nonce,
            &personalization_string,
        );
        let mut variant = <V as DrbgVariant>::instantiate(ii);
        let gi =
            <V as DrbgVariant>::GenerateInput::init(requested_number_of_bytes, &additional_input);
        variant.generate(gi).map_err(DrbgError::GenerateError)
    }
}
