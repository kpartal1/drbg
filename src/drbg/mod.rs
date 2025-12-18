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
    reseed_interval: u64,
    _pr: PhantomData<Pr>,
    _entropy: PhantomData<E>,
}

impl<'a, Pr: PredictionResistance, V: DrbgVariant<'a>, E: Entropy> DrbgVariant<'a>
    for Drbg<Pr, V, E>
{
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
            reseed_interval: V::MAX_RESEED_INTERVAL,
            _pr: PhantomData,
            _entropy: PhantomData,
        }
    }
    fn reseed(&mut self, input: Self::ReseedInput) {
        self.variant.reseed(input);
        self.reseed_counter = 1;
    }
    fn generate(&mut self, input: &mut Self::GenerateInput) -> Result<(), Self::GenerateError> {
        if Pr::must_reseed(self.reseed_counter, V::MAX_RESEED_INTERVAL) {
            return Err(DrbgError::ReseedRequired);
        }
        self.variant
            .generate(input)
            .map_err(DrbgError::GenerateError)?;
        self.reseed_counter += 1;
        Ok(())
    }
}

impl<'a, Pr: PredictionResistance, V: DrbgVariant<'a>, E: Entropy> Drbg<Pr, V, E> {
    pub fn set_reseed_interval(&mut self, reseed_interval: u64) {
        self.reseed_interval = reseed_interval;
    }

    pub fn new(personalization_string: &[u8]) -> Result<Self, E::Error> {
        let mut entropy_input = vec![0; Self::MIN_ENTROPY];
        E::try_fill_bytes(&mut entropy_input)?;
        let mut nonce = vec![0; Self::SECURITY_STRENGTH / 2];
        E::try_fill_bytes(&mut nonce)?;
        let ii = <Self as DrbgVariant>::InstantiateInput::init(
            &entropy_input,
            &nonce,
            personalization_string,
        );
        Ok(<Self as DrbgVariant>::instantiate(ii))
    }

    pub fn get_random_bytes(
        &mut self,
        buf: &'a mut [u8],
        additional_input: &'a [u8],
    ) -> Result<(), DrbgError<V::GenerateError, E::Error>> {
        let mut gi = <Self as DrbgVariant<'a>>::GenerateInput::init(
            buf,
            additional_input,
            self.reseed_counter,
        );
        match self.generate(&mut gi) {
            Ok(block) => Ok(block),
            Err(DrbgError::ReseedRequired) => {
                let mut entropy_input = vec![0; V::MIN_ENTROPY];
                E::try_fill_bytes(&mut entropy_input).map_err(DrbgError::EntropyError)?;
                let ri = <Self as DrbgVariant>::ReseedInput::init(&entropy_input, additional_input);
                self.reseed(ri);
                Ok(self.generate(&mut gi)?)
            }
            Err(e) => Err(e),
        }
    }
}
