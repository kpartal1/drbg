use rand_core::{OsRng, TryRngCore};
use std::fmt::{Debug, Display};

pub trait Entropy {
    type Error: Display + Debug;

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait CryptoEntropy: Entropy {}

impl Entropy for OsRng {
    type Error = <OsRng as TryRngCore>::Error;

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        OsRng.try_fill_bytes(bytes)
    }
}

impl CryptoEntropy for OsRng {}
