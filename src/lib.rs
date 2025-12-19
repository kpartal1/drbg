use ctr::{Aes128, Aes192, Aes256, Ctr};
use drbg::{Drbg, DrbgError, variant::DrbgVariant};
use hash_based::{Hash, Hmac};
use pr::{NoPr, Pr};
use rand::rngs::OsRng;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

mod ctr;
mod drbg;
mod entropy;
mod hash_based;
mod pr;

pub use entropy::Entropy;

macro_rules! define_reseed_interval {
    ($builder:ident, NoPr) => {
        impl<'a, E> $builder<'a, E> {
            pub fn reseed_interval(mut self, reseed_interval: u64) -> Self {
                self.reseed_interval = Some(reseed_interval);
                self
            }
        }
    };
    ($builder:ident, Pr) => {};
}

macro_rules! define_drbg_builder {
    ($name:ident, $builder:ident, $pr:tt, $variant:ident, $inner:ident) => {
        pub struct $builder<'a, E> {
            personalization_string: &'a [u8],
            reseed_interval: Option<u64>,
            entropy: std::marker::PhantomData<E>,
        }

        impl<'a, E> $builder<'a, E> {
            pub fn personalization_string(mut self, personalization_string: &'a [u8]) -> Self {
                self.personalization_string = personalization_string;
                self
            }

            pub fn entropy<En>(self) -> $builder<'a, En> {
                $builder {
                    personalization_string: self.personalization_string,
                    reseed_interval: self.reseed_interval,
                    entropy: std::marker::PhantomData::<En>,
                }
            }
        }

        impl<'a, E: Entropy> $builder<'a, E> {
            pub fn build(self) -> Result<$name<E>, E::Error> {
                let mut drbg = Drbg::<$pr, $variant<$inner>, E>::new(self.personalization_string)?;

                if let Some(reseed_interval) = self.reseed_interval {
                    drbg.set_reseed_interval(reseed_interval);
                }

                Ok($name(drbg))
            }

            pub fn random_bytes(
                self,
                buf: &mut [u8],
                additional_input: &[u8],
            ) -> Result<(), DrbgError<<$variant<$inner> as DrbgVariant>::GenerateError, E::Error>>
            {
                self.build()
                    .map_err(DrbgError::EntropyError)?
                    .get_random_bytes(buf, additional_input)
            }
        }

        define_reseed_interval!($builder, $pr);
    };
}

macro_rules! define_drbg {
    ($name:ident, $builder:ident, $pr:tt, $variant:ident, $inner:ident) => {
        pub struct $name<E = OsRng>(Drbg<$pr, $variant<$inner>, E>);

        impl<'a> $name {
            pub fn builder() -> $builder<'a, OsRng> {
                $builder {
                    personalization_string: &[],
                    reseed_interval: None,
                    entropy: std::marker::PhantomData,
                }
            }
        }

        impl<E: Entropy> $name<E> {
            pub fn get_random_bytes(
                &mut self,
                buf: &mut [u8],
                additional_input: &[u8],
            ) -> Result<(), DrbgError<<$variant<$inner> as DrbgVariant>::GenerateError, E::Error>>
            {
                self.0.get_random_bytes(buf, additional_input)
            }
        }

        define_drbg_builder!($name, $builder, $pr, $variant, $inner);
    };
}

macro_rules! define_all_drbg {
    ($(($name:ident, $builder:ident, $pr:tt, $variant:ident, $inner:ident)),*$(,)?) => {
        $(
            define_drbg!(
                $name,
                $builder,
                $pr,
                $variant,
                $inner
            );
        )*
    };
}

define_all_drbg!(
    (DrbgCtrAes256, DrbgCtrAes256Builder, NoPr, Ctr, Aes256),
    (DrbgPrCtrAes256, DrbgPrCtrAes256Builder, Pr, Ctr, Aes256),
    (DrbgCtrAes192, DrbgCtrAes192Builder, NoPr, Ctr, Aes192),
    (DrbgPrCtrAes192, DrbgPrCtrAes192Builder, Pr, Ctr, Aes192),
    (DrbgCtrAes128, DrbgCtrAes128Builder, NoPr, Ctr, Aes128),
    (DrbgPrCtrAes128, DrbgPrCtrAes128Builder, Pr, Ctr, Aes128),
    (DrbgHashSha224, DrbgHashSha224Builder, NoPr, Hash, Sha224),
    (DrbgPrHashSha224, DrbgPrHashSha224Builder, Pr, Hash, Sha224),
    (
        DrbgHashSha512_224,
        DrbgHashSha512_224Builder,
        NoPr,
        Hash,
        Sha512_224
    ),
    (
        DrbgPrHashSha512_224,
        DrbgPrHashSha512_224Builder,
        Pr,
        Hash,
        Sha512_224
    ),
    (DrbgHashSha256, DrbgHashSha256Builder, NoPr, Hash, Sha256),
    (DrbgPrHashSha256, DrbgPrHashSha256Builder, Pr, Hash, Sha256),
    (
        DrbgHashSha512_256,
        DrbgHashSha512_256Builder,
        NoPr,
        Hash,
        Sha512_256
    ),
    (
        DrbgPrHashSha512_256,
        DrbgPrHashSha512_256Builder,
        Pr,
        Hash,
        Sha512_256
    ),
    (DrbgHashSha384, DrbgHashSha384Builder, NoPr, Hash, Sha384),
    (DrbgPrHashSha384, DrbgPrHashSha384Builder, Pr, Hash, Sha384),
    (DrbgHashSha512, DrbgHashSha512Builder, NoPr, Hash, Sha512),
    (DrbgPrHashSha512, DrbgPrHashSha512Builder, Pr, Hash, Sha512),
    (DrbgHmacSha224, DrbgHmacSha224Builder, NoPr, Hmac, Sha224),
    (DrbgPrHmacSha224, DrbgPrHmacSha224Builder, Pr, Hmac, Sha224),
    (
        DrbgHmacSha512_224,
        DrbgHmacSha512_224Builder,
        NoPr,
        Hmac,
        Sha512_224
    ),
    (
        DrbgPrHmacSha512_224,
        DrbgPrHmacSha512_224Builder,
        Pr,
        Hmac,
        Sha512_224
    ),
    (DrbgHmacSha256, DrbgHmacSha256Builder, NoPr, Hmac, Sha256),
    (DrbgPrHmacSha256, DrbgPrHmacSha256Builder, Pr, Hmac, Sha256),
    (
        DrbgHmacSha512_256,
        DrbgHmacSha512_256Builder,
        NoPr,
        Hmac,
        Sha512_256
    ),
    (
        DrbgPrHmacSha512_256,
        DrbgPrHmacSha512_256Builder,
        Pr,
        Hmac,
        Sha512_256
    ),
    (DrbgHmacSha384, DrbgHmacSha384Builder, NoPr, Hmac, Sha384),
    (DrbgPrHmacSha384, DrbgPrHmacSha384Builder, Pr, Hmac, Sha384),
    (DrbgHmacSha512, DrbgHmacSha512Builder, NoPr, Hmac, Sha512),
    (DrbgPrHmacSha512, DrbgPrHmacSha512Builder, Pr, Hmac, Sha512),
);
