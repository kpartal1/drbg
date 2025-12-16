use ctr::{Aes128, Aes192, Aes256, Ctr};
use drbg::{Drbg, DrbgError, variant::DrbgVariant};
use hash_based::Hash;
use pr::{NoPr, Pr};
use rand::rngs::OsRng;
use sha2::Sha256;

mod ctr;
mod drbg;
mod entropy;
mod hash_based;
mod pr;

pub use entropy::Entropy;

macro_rules! define_drbg {
    ($name:ident, $pr:ty, $variant:ident, $inner:ident) => {
        pub struct $name<E = OsRng>(Drbg<$pr, $variant<$inner>, E>);

        impl $name {
            pub fn new(personalization_string: Vec<u8>) -> Result<Self, <OsRng as Entropy>::Error> {
                Drbg::new(personalization_string).map(Self)
            }

            pub fn random_bytes(
                requested_number_of_bytes: u32,
                personalization_string: Vec<u8>,
                additional_input: Vec<u8>,
            ) -> Result<
                Vec<u8>,
                DrbgError<
                    <$variant<$inner> as DrbgVariant>::GenerateError,
                    <OsRng as Entropy>::Error,
                >,
            > {
                Drbg::<$pr, $variant<$inner>, OsRng>::random_bytes(
                    requested_number_of_bytes,
                    personalization_string,
                    additional_input,
                )
            }
        }

        impl<E: Entropy> $name<E> {
            pub fn new_with_entropy(personalization_string: Vec<u8>) -> Result<Self, E::Error> {
                Drbg::new(personalization_string).map(Self)
            }

            pub fn random_bytes_with_entropy(
                requested_number_of_bytes: u32,
                personalization_string: Vec<u8>,
                additional_input: Vec<u8>,
            ) -> Result<
                Vec<u8>,
                DrbgError<<$variant<$inner> as DrbgVariant>::GenerateError, E::Error>,
            > {
                Drbg::<$pr, $variant<$inner>, E>::random_bytes(
                    requested_number_of_bytes,
                    personalization_string,
                    additional_input,
                )
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name::new(vec![]).unwrap()
            }
        }

        impl<E> std::ops::Deref for $name<E> {
            type Target = Drbg<$pr, $variant<$inner>, E>;

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
    (DrbgNoPrHashSha256, NoPr, Hash, Sha256),
    (DrbgPrHashSha256, Pr, Hash, Sha256),
);
