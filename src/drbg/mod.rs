use crate::{Entropy, drbg::variant::DrbgVariant, pr::PredictionResistance};
use std::{fmt::Debug, marker::PhantomData};

pub mod variant;

#[derive(Debug)]
pub enum DrbgError<V, E> {
    ReseedRequired,
    PersonalizationStringTooLong,
    AdditionalInputTooLong,
    GenerateError(V),
    EntropyError(E),
}

impl<V: Debug, E: Debug> std::fmt::Display for DrbgError<V, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrbgError::ReseedRequired => write!(f, "Reseed required."),
            DrbgError::PersonalizationStringTooLong => write!(f, "Personaliation String too long."),
            DrbgError::AdditionalInputTooLong => write!(f, "Additional input too long."),
            DrbgError::GenerateError(v) => write!(f, "Drbg Generate Error: {v:?}"),
            DrbgError::EntropyError(e) => write!(f, "Drbg Entropy Error: {e:?}"),
        }
    }
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

    pub fn new(
        personalization_string: &[u8],
    ) -> Result<Self, DrbgError<std::convert::Infallible, E::Error>> {
        if personalization_string.len() > V::MAX_PERSONALIZATION_STRING_LENGTH {
            return Err(DrbgError::PersonalizationStringTooLong);
        }
        let mut entropy = vec![0; Self::MIN_ENTROPY + Self::SECURITY_STRENGTH / 2];
        E::try_fill_bytes(&mut entropy).map_err(DrbgError::EntropyError)?;
        Ok(<Self as DrbgVariant>::instantiate(
            &entropy[..Self::MIN_ENTROPY],
            &entropy[Self::MIN_ENTROPY..],
            personalization_string,
        ))
    }

    pub fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
        additional_input: &[u8],
    ) -> Result<(), DrbgError<V::GenerateError, E::Error>> {
        if additional_input.len() > V::MAX_ADDITIONAL_INPUT_LENGTH {
            return Err(DrbgError::AdditionalInputTooLong);
        }
        for block in buf.chunks_mut(V::MAX_BYTES_PER_REQUEST) {
            match self.generate(block, additional_input, self.reseed_counter) {
                Err(DrbgError::ReseedRequired) => {
                    let mut entropy_input = vec![0; V::MIN_ENTROPY];
                    E::try_fill_bytes(&mut entropy_input).map_err(DrbgError::EntropyError)?;
                    self.reseed(&entropy_input, additional_input);
                    self.generate(block, additional_input, self.reseed_counter)?;
                }
                Err(e) => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }
}
