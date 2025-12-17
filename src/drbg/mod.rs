use crate::{
    Entropy,
    drbg::variant::{DrbgVariant, GenerateInputInit, InstantiateInputInit, ReseedInputInit},
    pr::PredictionResistance,
};
use std::marker::PhantomData;

pub mod variant;

#[derive(Debug)]
pub enum DrbgError<V, E> {
    ReseedRequired,
    GenerateError(V),
    EntropyError(E),
}

pub struct Drbg<Pr, V, E> {
    variant: V,
    reseed_counter: u64,
    _pr: PhantomData<Pr>,
    _entropy: PhantomData<E>,
}

impl<Pr: PredictionResistance, V: DrbgVariant, E: Entropy> DrbgVariant for Drbg<Pr, V, E> {
    const MAX_RESEED_INTERVAL: u64 = V::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = V::SECURITY_STRENGTH;

    type InstantiateInput = V::InstantiateInput;
    type ReseedInput = V::ReseedInput;
    type GenerateInput = V::GenerateInput;
    type GenerateError = DrbgError<V::GenerateError, E::Error>;

    fn instantiate(input: Self::InstantiateInput) -> Self {
        Self {
            variant: V::instantiate(input),
            reseed_counter: 1,
            _pr: PhantomData,
            _entropy: PhantomData,
        }
    }
    fn reseed(&mut self, input: Self::ReseedInput) {
        self.variant.reseed(input);
        self.reseed_counter = 1;
    }
    fn generate(&mut self, input: Self::GenerateInput) -> Result<Vec<u8>, Self::GenerateError> {
        if Pr::must_reseed(self.reseed_counter, V::MAX_RESEED_INTERVAL) {
            return Err(DrbgError::ReseedRequired);
        }
        let res = self
            .variant
            .generate(input)
            .map_err(DrbgError::GenerateError)?;
        self.reseed_counter += 1;
        Ok(res)
    }
}

impl<Pr: PredictionResistance, V: DrbgVariant, E: Entropy> Drbg<Pr, V, E> {
    pub fn new(personalization_string: Vec<u8>) -> Result<Self, E::Error> {
        let mut entropy_input = vec![0; Self::MIN_ENTROPY];
        E::try_fill_bytes(&mut entropy_input)?;
        let mut nonce = vec![0; Self::SECURITY_STRENGTH / 2];
        E::try_fill_bytes(&mut nonce)?;
        let ii = <Self as DrbgVariant>::InstantiateInput::init(
            &entropy_input,
            &nonce,
            &personalization_string,
        );
        Ok(<Self as DrbgVariant>::instantiate(ii))
    }

    pub fn get_random_bytes(
        &mut self,
        requested_number_of_bytes: usize,
        additional_input: Vec<u8>,
    ) -> Result<Vec<u8>, DrbgError<V::GenerateError, E::Error>> {
        let gi = <Self as DrbgVariant>::GenerateInput::init(
            requested_number_of_bytes,
            &additional_input,
            self.reseed_counter,
        );
        match self.generate(gi) {
            Ok(block) => Ok(block),
            Err(_) => {
                let mut entropy_input = vec![0; V::MIN_ENTROPY];
                E::try_fill_bytes(&mut entropy_input).map_err(DrbgError::EntropyError)?;
                let ri =
                    <Self as DrbgVariant>::ReseedInput::init(&entropy_input, &additional_input);
                self.reseed(ri);
                let gi = <Self as DrbgVariant>::GenerateInput::init(
                    requested_number_of_bytes,
                    &additional_input,
                    self.reseed_counter,
                );
                Ok(self.generate(gi)?)
            }
        }
    }

    pub fn random_bytes(
        requested_number_of_bytes: usize,
        personalization_string: Vec<u8>,
        additional_input: Vec<u8>,
    ) -> Result<Vec<u8>, DrbgError<V::GenerateError, E::Error>> {
        let mut entropy_input = vec![0; V::MIN_ENTROPY];
        E::try_fill_bytes(&mut entropy_input).map_err(DrbgError::EntropyError)?;
        let mut nonce = vec![0; V::SECURITY_STRENGTH / 2];
        E::try_fill_bytes(&mut nonce).map_err(DrbgError::EntropyError)?;
        let ii = <Self as DrbgVariant>::InstantiateInput::init(
            &entropy_input,
            &nonce,
            &personalization_string,
        );
        let mut drbg = Self::instantiate(ii);
        let gi = <Self as DrbgVariant>::GenerateInput::init(
            requested_number_of_bytes,
            &additional_input,
            drbg.reseed_counter,
        );
        drbg.generate(gi)
    }
}
