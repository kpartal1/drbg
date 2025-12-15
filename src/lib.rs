use ctr::{Aes128, Aes192, Aes256, Ctr};
use drbg::{Drbg, variant::Variant};
use pr::{NoPr, Pr};
use rand::rngs::OsRng;

mod ctr;
mod drbg;
mod pr;

pub use drbg::entropy::Entropy;

macro_rules! define_drbg {
    ($name:ident, $pr:ty, $variant:ident, $inner:ident) => {
        pub struct $name<E = OsRng>(Drbg<Variant<$pr, $variant<$inner>>, E>);

        impl $name<OsRng> {
            pub fn new(personalization_string: Vec<u8>) -> Result<Self, <OsRng as Entropy>::Error> {
                Drbg::new(personalization_string).map(Self)
            }
        }

        impl<E: Entropy> $name<E> {
            pub fn new_with_entropy(personalization_string: Vec<u8>) -> Result<Self, E::Error> {
                Drbg::new(personalization_string).map(Self)
            }
        }

        impl<E> std::ops::Deref for $name<E> {
            type Target = Drbg<Variant<$pr, $variant<$inner>>, E>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<E> std::ops::DerefMut for $name<E> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

macro_rules! define_all_drbg {
    ($(($name:ident, $pr:ty, $variant:ident, $inner:ident)),*$(,)?) => {
        $(
            define_drbg!(
                $name,
                $pr,
                $variant,
                $inner
            );
        )*
    };
}

define_all_drbg!(
    (DrbgNoPrCtrAes256, NoPr, Ctr, Aes256),
    (DrbgPrCtrAes256, Pr, Ctr, Aes256),
    (DrbgNoPrCtrAes192, NoPr, Ctr, Aes192),
    (DrbgPrCtrAes192, Pr, Ctr, Aes192),
    (DrbgNoPrCtrAes128, NoPr, Ctr, Aes128),
    (DrbgPrCtrAes128, Pr, Ctr, Aes128),
);
