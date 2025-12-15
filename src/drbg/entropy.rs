use rand::{TryRngCore, rngs::OsRng};
use std::fmt::Debug;

pub trait Entropy {
    type Error: Debug;

    fn try_fill_bytes(bytes: &mut [u8]) -> Result<(), Self::Error>;
    fn fill_bytes(bytes: &mut [u8]) {
        Self::try_fill_bytes(bytes).expect(
            "Failed to generate entropy. Use try_get_entropy if your entropy request may fail.",
        )
    }
}

impl Entropy for OsRng {
    type Error = <OsRng as TryRngCore>::Error;

    fn try_fill_bytes(bytes: &mut [u8]) -> Result<(), Self::Error> {
        OsRng.try_fill_bytes(bytes)
    }
}
