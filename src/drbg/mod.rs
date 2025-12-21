use crate::{
    Entropy,
    drbg::variant::{DrbgVariant, ReseedRequired},
    pr::PredictionResistance,
};
use std::marker::PhantomData;

pub mod variant;

#[derive(Debug)]
pub enum DrbgError<E> {
    ReseedIntervalTooLong,
    ReseedIntervalTooShort,
    PersonalizationStringTooLong,
    AdditionalInputTooLong,
    EntropyError(E),
}

impl<E: std::fmt::Display> std::fmt::Display for DrbgError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrbgError::ReseedIntervalTooLong => write!(f, "Reseed interval too long."),
            DrbgError::ReseedIntervalTooShort => {
                write!(f, "Reseed interval must be greater than 0.")
            }
            DrbgError::PersonalizationStringTooLong => {
                write!(f, "Personalization string too long.")
            }
            DrbgError::AdditionalInputTooLong => write!(f, "Additional input too long."),
            DrbgError::EntropyError(e) => write!(f, "Drbg Entropy Error: {e}"),
        }
    }
}

pub struct Variant<Pr, V> {
    variant: V,
    reseed_counter: u64,
    reseed_interval: u64,
    _pr: PhantomData<Pr>,
}

impl<Pr: PredictionResistance, V: DrbgVariant> DrbgVariant for Variant<Pr, V> {
    const MAX_RESEED_INTERVAL: u64 = V::MAX_RESEED_INTERVAL;
    const SECURITY_STRENGTH: usize = V::SECURITY_STRENGTH;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        Self {
            variant: V::instantiate(entropy_input, nonce, personalization_string),
            reseed_counter: 1,
            reseed_interval: V::MAX_RESEED_INTERVAL,
            _pr: PhantomData,
        }
    }
    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        self.variant.reseed(entropy_input, additional_input);
        self.reseed_counter = 1;
    }

    fn generate(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
        reseed_counter: u64,
    ) -> Result<(), ReseedRequired> {
        if Pr::must_reseed(self.reseed_counter, self.reseed_interval) {
            return Err(ReseedRequired);
        }
        let _ = self
            .variant
            .generate(bytes, additional_input, reseed_counter);
        self.reseed_counter += 1;
        Ok(())
    }
}

pub struct Drbg<Pr, V, E> {
    variant: Variant<Pr, V>,
    entropy: E,
}

impl<Pr: PredictionResistance, V: DrbgVariant, E: Entropy> Drbg<Pr, V, E> {
    pub fn set_reseed_interval(&mut self, reseed_interval: u64) -> Result<(), DrbgError<E::Error>> {
        if reseed_interval > V::MAX_RESEED_INTERVAL {
            return Err(DrbgError::ReseedIntervalTooLong);
        }
        self.variant.reseed_interval = reseed_interval;
        Ok(())
    }

    pub fn new(
        mut entropy: E,
        nonce: &[u8],
        personalization_string: &[u8],
    ) -> Result<Self, DrbgError<E::Error>> {
        if personalization_string.len() > V::MAX_PERSONALIZATION_STRING_LENGTH {
            return Err(DrbgError::PersonalizationStringTooLong);
        }
        let mut entropy_input = vec![0; V::MIN_ENTROPY];
        entropy
            .fill_bytes(&mut entropy_input)
            .map_err(DrbgError::EntropyError)?;
        Ok(Self {
            variant: Variant::instantiate(&entropy_input, nonce, personalization_string),
            entropy,
        })
    }

    pub fn fill_bytes(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
    ) -> Result<(), DrbgError<E::Error>> {
        if additional_input.len() > V::MAX_ADDITIONAL_INPUT_LENGTH {
            return Err(DrbgError::AdditionalInputTooLong);
        }
        for block in bytes.chunks_mut(V::MAX_BYTES_PER_REQUEST) {
            if Pr::is_pr()
                || self
                    .variant
                    .generate(block, additional_input, self.variant.reseed_counter)
                    .is_err()
            {
                let mut entropy_input = vec![0; V::MIN_ENTROPY];
                self.entropy
                    .fill_bytes(&mut entropy_input)
                    .map_err(DrbgError::EntropyError)?;
                self.variant.reseed(&entropy_input, additional_input);
                // Section 9.3.1 Step 7.4
                let _ = self
                    .variant
                    .generate(block, &[], self.variant.reseed_counter);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn reseed(&mut self, additional_input: &[u8]) -> Result<(), E::Error> {
        let mut entropy_input = vec![0; V::MIN_ENTROPY];
        self.entropy.fill_bytes(&mut entropy_input)?;
        self.variant.reseed(&entropy_input, additional_input);
        Ok(())
    }
}
