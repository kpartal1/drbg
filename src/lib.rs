use ctr::{Aes128, Aes192, Aes256, Ctr};
use drbg::{Drbg, DrbgError, variant::DrbgVariant};
use hash_based::{Hash, Hmac};
use pr::{NoPr, Pr};
use rand_core::{OsRng, TryCryptoRng, TryRngCore};
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

mod ctr;
mod drbg;
mod entropy;
mod hash_based;
mod pr;

pub use entropy::{CryptoEntropy, Entropy};

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
            nonce: Option<&'a [u8]>,
            entropy: E,
        }

        impl<'a, E> $builder<'a, E> {
            pub fn personalization_string(mut self, personalization_string: &'a [u8]) -> Self {
                self.personalization_string = personalization_string;
                self
            }

            pub fn nonce(mut self, nonce: &'a [u8]) -> Self {
                self.nonce = Some(nonce);
                self
            }

            pub fn entropy<E2: Entropy>(self, entropy: E2) -> $builder<'a, E2> {
                $builder {
                    personalization_string: self.personalization_string,
                    reseed_interval: self.reseed_interval,
                    nonce: self.nonce,
                    entropy,
                }
            }
        }

        impl<'a, E: Entropy> $builder<'a, E> {
            pub fn build(mut self) -> Result<$name<E>, DrbgError<E::Error>> {
                let mut drbg = match self.nonce {
                    Some(nonce) => Drbg::<$pr, $variant<$inner>, E>::new(
                        self.entropy,
                        nonce,
                        self.personalization_string,
                    )?,
                    None => {
                        let mut nonce =
                            vec![0; <$variant<$inner> as DrbgVariant>::SECURITY_STRENGTH / 2];
                        self.entropy
                            .fill_bytes(&mut nonce)
                            .map_err(DrbgError::EntropyError)?;
                        Drbg::<$pr, $variant<$inner>, E>::new(
                            self.entropy,
                            &nonce,
                            self.personalization_string,
                        )?
                    }
                };

                if let Some(reseed_interval) = self.reseed_interval {
                    if reseed_interval < 1 {
                        return Err(DrbgError::ReseedIntervalTooShort);
                    }
                    drbg.set_reseed_interval(reseed_interval)?;
                }

                Ok($name(drbg))
            }
        }

        define_reseed_interval!($builder, $pr);
    };
}

macro_rules! define_drbg {
    ($name:ident, $builder:ident, $pr:tt, $variant:ident, $inner:ident) => {
        pub struct $name<E = OsRng>(Drbg<$pr, $variant<$inner>, E>);

        impl<'a> $name {
            pub fn new() -> Result<Self, DrbgError<<OsRng as TryRngCore>::Error>> {
                Self::builder().build()
            }

            pub fn builder() -> $builder<'a, OsRng> {
                $builder {
                    personalization_string: &[],
                    reseed_interval: None,
                    nonce: None,
                    entropy: OsRng,
                }
            }
        }

        impl<E: Entropy> $name<E> {
            pub fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), DrbgError<E::Error>> {
                self.fill_bytes_with_ai(bytes, &[])
            }

            pub fn fill_bytes_with_ai(
                &mut self,
                bytes: &mut [u8],
                additional_input: &[u8],
            ) -> Result<(), DrbgError<E::Error>> {
                self.0.fill_bytes(bytes, additional_input)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                match Self::new() {
                    Ok(drbg) => drbg,
                    Err(e) => panic!("Failed to instantiate default DRBG. Use new() instead to explicitly handle failure.\nERROR: {e}"),
                }
            }
        }

        impl<E: Entropy> TryRngCore for $name<E> {
            type Error = DrbgError<E::Error>;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                let mut bytes = [0; std::mem::size_of::<u32>()];
                self.try_fill_bytes(&mut bytes)?;
                Ok(u32::from_ne_bytes(bytes))
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                let mut bytes = [0; std::mem::size_of::<u64>()];
                self.try_fill_bytes(&mut bytes)?;
                Ok(u64::from_ne_bytes(bytes))
            }

            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                self.fill_bytes(dst)
            }
        }

        impl<E: CryptoEntropy> TryCryptoRng for $name<E> {}

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
    (DrbgCtrAes128, DrbgCtrAes128Builder, NoPr, Ctr, Aes128),
    (DrbgPrCtrAes128, DrbgPrCtrAes128Builder, Pr, Ctr, Aes128),
    (DrbgCtrAes192, DrbgCtrAes192Builder, NoPr, Ctr, Aes192),
    (DrbgPrCtrAes192, DrbgPrCtrAes192Builder, Pr, Ctr, Aes192),
    (DrbgCtrAes256, DrbgCtrAes256Builder, NoPr, Ctr, Aes256),
    (DrbgPrCtrAes256, DrbgPrCtrAes256Builder, Pr, Ctr, Aes256),
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

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

    use crate::{
        DrbgCtrAes128, DrbgCtrAes192, DrbgCtrAes256, DrbgHashSha224, DrbgHashSha256,
        DrbgHashSha384, DrbgHashSha512, DrbgHashSha512_224, DrbgHashSha512_256, DrbgHmacSha224,
        DrbgHmacSha256, DrbgHmacSha384, DrbgHmacSha512, DrbgHmacSha512_224, DrbgHmacSha512_256,
        DrbgPrCtrAes128, DrbgPrCtrAes192, DrbgPrCtrAes256, DrbgPrHashSha224, DrbgPrHashSha256,
        DrbgPrHashSha384, DrbgPrHashSha512, DrbgPrHashSha512_224, DrbgPrHashSha512_256,
        DrbgPrHmacSha224, DrbgPrHmacSha256, DrbgPrHmacSha384, DrbgPrHmacSha512,
        DrbgPrHmacSha512_224, DrbgPrHmacSha512_256, Entropy, drbg::DrbgError,
    };

    #[derive(Default)]
    struct MockEntropy {
        bytes: Vec<Vec<u8>>,
        pos: usize,
    }

    impl Entropy for MockEntropy {
        type Error = std::convert::Infallible;

        fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let entropy = &self.bytes[self.pos];
            bytes.copy_from_slice(entropy);
            self.pos += 1;
            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct PrTrial {
        entropy_input: String,
        nonce: String,
        personalization_string: String,
        additional_inputs: Vec<String>,
        entropy_input_prs: Vec<String>,
        returned_bits: String,
    }

    #[derive(Debug, Default)]
    struct PrTestCase {
        name: String,
        trials: Vec<PrTrial>,
    }

    fn generate_pr_test_cases(path: impl AsRef<Path>) -> Vec<PrTestCase> {
        let file = File::open(path).unwrap();

        let mut cases = Vec::new();
        let mut current_name = String::new();
        let mut trials = Vec::new();
        let mut current_trial = PrTrial::default();
        let mut skip = false;
        let mut count = 0;

        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let line = line.trim();

            if line.starts_with('[') && !line.contains('=') {
                current_name = line
                    .trim_matches(&['[', ']'][..])
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_string();
                skip =
                    line.contains("no df") || line.contains("3KeyTDEA") || line.contains("SHA-1");
                continue;
            }

            if skip {
                continue;
            }

            if line.starts_with("COUNT") {
                count += 1;
            } else if let Some((k, v)) = line.split_once(" = ") {
                match k {
                    "EntropyInput" => current_trial.entropy_input = v.to_string(),
                    "Nonce" => current_trial.nonce = v.to_string(),
                    "PersonalizationString" => current_trial.personalization_string = v.to_string(),
                    "AdditionalInput" => current_trial.additional_inputs.push(v.to_string()),
                    "EntropyInputPR" => current_trial.entropy_input_prs.push(v.to_string()),
                    "ReturnedBits" => {
                        current_trial.returned_bits = v.to_string();
                        trials.push(current_trial.clone());
                        current_trial = PrTrial::default();
                        if count == 15 {
                            cases.push(PrTestCase {
                                name: current_name.clone(),
                                trials: trials.clone(),
                            });
                            trials.clear();
                            count = 0;
                        }
                    }
                    _ => {}
                }
            }
        }

        cases
    }

    #[test]
    fn test_pr_hash() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_pr_test_cases("drbgtestvectors/drbgvectors_pr_true/Hash_DRBG.rsp") {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(trial.returned_bits).unwrap();
                let mut entropy = MockEntropy::default();
                entropy
                    .bytes
                    .push(hex::decode(trial.entropy_input).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_prs[0]).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_prs[1]).unwrap());

                match case.name.as_str() {
                    "SHA-224" => {
                        println!("SHA-224");
                        let mut drbg = DrbgPrHashSha224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-256" => {
                        println!("SHA-256");
                        let mut drbg = DrbgPrHashSha256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-384" => {
                        println!("SHA-384");
                        let mut drbg = DrbgPrHashSha384::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512" => {
                        println!("SHA-512");
                        let mut drbg = DrbgPrHashSha512::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/224" => {
                        println!("SHA-512/224");
                        let mut drbg = DrbgPrHashSha512_224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/256" => {
                        println!("SHA-512/256");
                        let mut drbg = DrbgPrHashSha512_256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    name => unreachable!("Unexpected cipher type {name} in PR test vectors."),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_pr_hmac() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_pr_test_cases("drbgtestvectors/drbgvectors_pr_true/HMAC_DRBG.rsp") {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(trial.returned_bits).unwrap();
                let mut entropy = MockEntropy::default();
                entropy
                    .bytes
                    .push(hex::decode(trial.entropy_input).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_prs[0]).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_prs[1]).unwrap());

                match case.name.as_str() {
                    "SHA-224" => {
                        println!("SHA-224");
                        let mut drbg = DrbgPrHmacSha224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-256" => {
                        println!("SHA-256");
                        let mut drbg = DrbgPrHmacSha256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-384" => {
                        println!("SHA-384");
                        let mut drbg = DrbgPrHmacSha384::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512" => {
                        println!("SHA-512");
                        let mut drbg = DrbgPrHmacSha512::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/224" => {
                        println!("SHA-512/224");
                        let mut drbg = DrbgPrHmacSha512_224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/256" => {
                        println!("SHA-512/256");
                        let mut drbg = DrbgPrHmacSha512_256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    name => unreachable!("Unexpected cipher type {name} in PR test vectors."),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_pr_ctr() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_pr_test_cases("drbgtestvectors/drbgvectors_pr_true/CTR_DRBG.rsp") {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(trial.returned_bits).unwrap();
                let mut entropy = MockEntropy::default();
                entropy
                    .bytes
                    .push(hex::decode(trial.entropy_input).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_prs[0]).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_prs[1]).unwrap());

                match case.name.as_str() {
                    "AES-128" => {
                        println!("AES-128");
                        let mut drbg = DrbgPrCtrAes128::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "AES-192" => {
                        println!("AES-192");
                        let mut drbg = DrbgPrCtrAes192::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "AES-256" => {
                        println!("AES-256");
                        let mut drbg = DrbgPrCtrAes256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    name => unreachable!("Unexpected cipher type {name} in PR test vectors."),
                }
            }
        }
        Ok(())
    }

    #[derive(Clone, Debug, Default)]
    struct Trial {
        entropy_input: String,
        nonce: String,
        personalization_string: String,
        entropy_input_reseed: String,
        additional_input_reseed: String,
        additional_inputs: Vec<String>,
        returned_bits: String,
    }

    #[derive(Default, Debug)]
    struct TestCase {
        name: String,
        trials: Vec<Trial>,
    }

    fn generate_no_pr_test_cases(path: impl AsRef<Path>) -> Vec<TestCase> {
        let file = File::open(path).unwrap();

        let mut cases = Vec::new();
        let mut current_name = String::new();
        let mut trials = Vec::new();
        let mut current_trial = Trial::default();
        let mut skip = false;
        let mut count = 0;

        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let line = line.trim();

            if line.starts_with('[') && !line.contains('=') {
                current_name = line
                    .trim_matches(&['[', ']'][..])
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_string();
                skip =
                    line.contains("no df") || line.contains("3KeyTDEA") || line.contains("SHA-1");
                continue;
            }

            if skip {
                continue;
            }

            if line.starts_with("COUNT") {
                count += 1;
            } else if let Some((k, v)) = line.split_once(" = ") {
                match k {
                    "EntropyInput" => current_trial.entropy_input = v.to_string(),
                    "Nonce" => current_trial.nonce = v.to_string(),
                    "PersonalizationString" => current_trial.personalization_string = v.to_string(),
                    "EntropyInputReseed" => current_trial.entropy_input_reseed = v.to_string(),
                    "AdditionalInputReseed" => {
                        current_trial.additional_input_reseed = v.to_string()
                    }
                    "AdditionalInput" => current_trial.additional_inputs.push(v.to_string()),
                    "ReturnedBits" => {
                        current_trial.returned_bits = v.to_string();
                        trials.push(current_trial.clone());
                        current_trial = Trial::default();
                        if count == 15 {
                            cases.push(TestCase {
                                name: current_name.clone(),
                                trials: trials.clone(),
                            });
                            trials.clear();
                            count = 0;
                        }
                    }
                    _ => {}
                }
            }
        }

        cases
    }

    #[test]
    fn test_no_pr_hash() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_no_pr_test_cases("drbgtestvectors/drbgvectors_pr_false/Hash_DRBG.rsp")
        {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(trial.returned_bits).unwrap();
                let mut entropy = MockEntropy::default();
                entropy
                    .bytes
                    .push(hex::decode(trial.entropy_input).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_reseed).unwrap());

                match case.name.as_str() {
                    "SHA-224" => {
                        println!("SHA-224");
                        let mut drbg = DrbgHashSha224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-256" => {
                        println!("SHA-256");
                        let mut drbg = DrbgHashSha256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-384" => {
                        println!("SHA-384");
                        let mut drbg = DrbgHashSha384::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512" => {
                        println!("SHA-512");
                        let mut drbg = DrbgHashSha512::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/224" => {
                        println!("SHA-512/224");
                        let mut drbg = DrbgHashSha512_224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/256" => {
                        println!("SHA-512/256");
                        let mut drbg = DrbgHashSha512_256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    name => unreachable!("Unexpected cipher type {name} in PR test vectors."),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_no_pr_hmac() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_no_pr_test_cases("drbgtestvectors/drbgvectors_pr_false/HMAC_DRBG.rsp")
        {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(trial.returned_bits).unwrap();
                let mut entropy = MockEntropy::default();
                entropy
                    .bytes
                    .push(hex::decode(trial.entropy_input).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_reseed).unwrap());

                match case.name.as_str() {
                    "SHA-224" => {
                        println!("SHA-224");
                        let mut drbg = DrbgHmacSha224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-256" => {
                        println!("SHA-256");
                        let mut drbg = DrbgHmacSha256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-384" => {
                        println!("SHA-384");
                        let mut drbg = DrbgHmacSha384::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512" => {
                        println!("SHA-512");
                        let mut drbg = DrbgHmacSha512::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/224" => {
                        println!("SHA-512/224");
                        let mut drbg = DrbgHmacSha512_224::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "SHA-512/256" => {
                        println!("SHA-512/256");
                        let mut drbg = DrbgHmacSha512_256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    name => unreachable!("Unexpected cipher type {name} in PR test vectors."),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_no_pr_ctr() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_no_pr_test_cases("drbgtestvectors/drbgvectors_pr_false/CTR_DRBG.rsp") {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(trial.returned_bits).unwrap();
                let mut entropy = MockEntropy::default();
                entropy
                    .bytes
                    .push(hex::decode(trial.entropy_input).unwrap());
                entropy
                    .bytes
                    .push(hex::decode(&trial.entropy_input_reseed).unwrap());

                match case.name.as_str() {
                    "AES-128" => {
                        println!("AES-128");
                        let mut drbg = DrbgCtrAes128::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "AES-192" => {
                        println!("AES-192");
                        let mut drbg = DrbgCtrAes192::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    "AES-256" => {
                        println!("AES-256");
                        let mut drbg = DrbgCtrAes256::builder()
                            .entropy(entropy)
                            .personalization_string(
                                &hex::decode(trial.personalization_string).unwrap(),
                            )
                            .nonce(&hex::decode(trial.nonce).unwrap())
                            .build()?;

                        drbg.0
                            .reseed(&hex::decode(trial.additional_input_reseed).unwrap());

                        let mut bytes = vec![0; returned_bits.len()];
                        if trial.additional_inputs.is_empty() {
                            drbg.fill_bytes(&mut bytes)?;
                            drbg.fill_bytes(&mut bytes)?;
                        } else {
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[0]).unwrap(),
                            )?;
                            drbg.fill_bytes_with_ai(
                                &mut bytes,
                                &hex::decode(&trial.additional_inputs[1]).unwrap(),
                            )?;
                        }

                        assert!(bytes == returned_bits);
                    }
                    name => unreachable!("Unexpected cipher type {name} in No-PR test vectors."),
                }
            }
        }
        Ok(())
    }
}
