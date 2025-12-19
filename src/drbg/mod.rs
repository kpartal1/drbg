use crate::{Entropy, drbg::variant::DrbgVariant, pr::PredictionResistance};
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
    reseed_interval: u64,
    _pr: PhantomData<Pr>,
    _entropy: PhantomData<E>,
}

impl<Pr: PredictionResistance, V: DrbgVariant, E: Entropy> DrbgVariant for Drbg<Pr, V, E> {
    const MAX_RESEED_INTERVAL: u64 = V::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = V::SECURITY_STRENGTH;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        Self {
            variant: V::instantiate(entropy_input, nonce, personalization_string),
            reseed_counter: 1,
            reseed_interval: V::MAX_RESEED_INTERVAL,
            _pr: PhantomData,
            _entropy: PhantomData,
        }
    }
    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        self.variant.reseed(entropy_input, additional_input);
        self.reseed_counter = 1;
    }

    type GenerateError = DrbgError<V::GenerateError, E::Error>;
    fn generate(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
        reseed_counter: u64,
    ) -> Result<(), Self::GenerateError> {
        if Pr::must_reseed(self.reseed_counter, V::MAX_RESEED_INTERVAL) {
            return Err(DrbgError::ReseedRequired);
        }
        self.variant
            .generate(bytes, additional_input, reseed_counter)
            .map_err(DrbgError::GenerateError)?;
        self.reseed_counter += 1;
        Ok(())
    }
}

impl<Pr: PredictionResistance, V: DrbgVariant, E: Entropy> Drbg<Pr, V, E> {
    pub fn set_reseed_interval(&mut self, reseed_interval: u64) {
        self.reseed_interval = reseed_interval;
    }

    pub fn new(personalization_string: &[u8]) -> Result<Self, E::Error> {
        let mut entropy_input = vec![0; Self::MIN_ENTROPY];
        E::try_fill_bytes(&mut entropy_input)?;
        let mut nonce = vec![0; Self::SECURITY_STRENGTH / 2];
        E::try_fill_bytes(&mut nonce)?;
        Ok(<Self as DrbgVariant>::instantiate(
            &entropy_input,
            &nonce,
            personalization_string,
        ))
    }

    pub fn get_random_bytes(
        &mut self,
        buf: &mut [u8],
        additional_input: &[u8],
    ) -> Result<(), DrbgError<V::GenerateError, E::Error>> {
        match self.generate(buf, additional_input, self.reseed_counter) {
            Ok(block) => Ok(block),
            Err(DrbgError::ReseedRequired) => {
                let mut entropy_input = vec![0; V::MIN_ENTROPY];
                E::try_fill_bytes(&mut entropy_input).map_err(DrbgError::EntropyError)?;
                self.reseed(&entropy_input, additional_input);
                Ok(self.generate(buf, additional_input, self.reseed_counter)?)
            }
            Err(e) => Err(e),
        }
    }
}
