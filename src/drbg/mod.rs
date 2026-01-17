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
    NonceTooLong,
    NonceTooShort,
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
            DrbgError::NonceTooLong => {
                write!(f, "Nonce cannot be longer than {} bytes.", 1u64 << 32)
            }
            DrbgError::NonceTooShort => write!(
                f,
                "Nonce must be at least security_strength / 2 bytes long."
            ),
            DrbgError::EntropyError(e) => write!(f, "Drbg Entropy Error: {e}"),
        }
    }
}

pub struct Variant<V> {
    variant: V,
    reseed_counter: u64,
    reseed_interval: u64,
}

// Shared reseeding behavior across DRBG variants.
// They all start with reseed_counter at 1, set it to 1 after a reseed, and add 1 to it after a generate.
// I decided to abstract this behavior to simplify the variants.
impl<V: DrbgVariant> Variant<V> {
    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        Self {
            variant: V::instantiate(entropy_input, nonce, personalization_string),
            reseed_counter: 1,
            reseed_interval: V::MAX_RESEED_INTERVAL,
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
        if self.reseed_counter > self.reseed_interval {
            return Err(ReseedRequired);
        }
        self.variant
            .generate(bytes, additional_input, reseed_counter);
        self.reseed_counter += 1;
        Ok(())
    }
}

pub struct Drbg<Pr, V, E> {
    variant: Variant<V>,
    entropy: E,
    _pr: PhantomData<Pr>,
}

impl<Pr: PredictionResistance, V: DrbgVariant, E: Entropy> Drbg<Pr, V, E> {
    pub fn set_reseed_interval(&mut self, reseed_interval: u64) {
        self.variant.reseed_interval = reseed_interval;
    }

    // Section 9.1
    pub fn new(
        mut entropy: E,
        nonce: &[u8],
        personalization_string: &[u8],
    ) -> Result<Self, DrbgError<E::Error>> {
        // Section 9.1 Step 6
        let mut entropy_input = vec![0; V::MIN_ENTROPY];
        entropy
            .fill_bytes(&mut entropy_input)
            .map_err(DrbgError::EntropyError)?;
        Ok(Self {
            // Section 9.1 Step 9
            variant: Variant::instantiate(&entropy_input, nonce, personalization_string),
            entropy,
            _pr: PhantomData,
        })
    }

    // Section 9.2
    fn reseed(&mut self, additional_input: &[u8]) -> Result<(), DrbgError<E::Error>> {
        // Section 9.2 Step 4
        // We always use MIN_ENTROPY here for simplicity. Our entropy will be conditioned by df anyway.
        let mut entropy_input = vec![0; V::MIN_ENTROPY];
        self.entropy
            .fill_bytes(&mut entropy_input)
            .map_err(DrbgError::EntropyError)?;
        // Section 9.2 Step 5
        self.variant.reseed(&entropy_input, additional_input);
        Ok(())
    }

    // Section 9.3
    pub fn fill_bytes(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
    ) -> Result<(), DrbgError<E::Error>> {
        if additional_input.len() > V::MAX_ADDITIONAL_INPUT_LENGTH {
            return Err(DrbgError::AdditionalInputTooLong);
        }
        // Section 9.3.1 Step 2
        // We operate over MAX_BYTES_PER_REQUEST chunks so if we need to reseed, we do.
        for block in bytes.chunks_mut(V::MAX_BYTES_PER_REQUEST) {
            // Section 9.3.1 Step 7
            if Pr::IS_PR
                || self
                    .variant
                    .generate(block, additional_input, self.variant.reseed_counter)
                    .is_err()
            {
                // Section 9.3.1 Step 7.1
                self.reseed(additional_input)?;
                // Section 9.3.1 Step 7.4
                // If additional_input was passed into reseed, it is null in the call to generate.
                // We call generate on the inner variant here to avoid the redundant reseed_counter check.
                self.variant
                    .variant
                    .generate(block, &[], self.variant.reseed_counter);
                // Since we avoided the reseed_counter check, we need to increment reseed_counter here instead.
                self.variant.reseed_counter += 1;
            }
        }
        Ok(())
    }
}
