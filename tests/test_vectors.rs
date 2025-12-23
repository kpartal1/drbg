#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

    use kondrbg::{
        DrbgCtrAes128, DrbgCtrAes192, DrbgCtrAes256, DrbgError, DrbgHashSha224, DrbgHashSha256,
        DrbgHashSha384, DrbgHashSha512, DrbgHashSha512_224, DrbgHashSha512_256, DrbgHmacSha224,
        DrbgHmacSha256, DrbgHmacSha384, DrbgHmacSha512, DrbgHmacSha512_224, DrbgHmacSha512_256,
        DrbgPrCtrAes128, DrbgPrCtrAes192, DrbgPrCtrAes256, DrbgPrHashSha224, DrbgPrHashSha256,
        DrbgPrHashSha384, DrbgPrHashSha512, DrbgPrHashSha512_224, DrbgPrHashSha512_256,
        DrbgPrHmacSha224, DrbgPrHmacSha256, DrbgPrHmacSha384, DrbgPrHmacSha512,
        DrbgPrHmacSha512_224, DrbgPrHmacSha512_256, Entropy,
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

        for line in BufReader::new(file).lines().map(|l| l.unwrap()) {
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

    fn fill_pr_entropy(trial: &PrTrial) -> MockEntropy {
        let mut entropy = MockEntropy::default();
        entropy
            .bytes
            .push(hex::decode(&trial.entropy_input).unwrap());
        entropy
            .bytes
            .push(hex::decode(&trial.entropy_input_prs[0]).unwrap());
        entropy
            .bytes
            .push(hex::decode(&trial.entropy_input_prs[1]).unwrap());
        entropy
    }

    #[test]
    fn test_pr_hash() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_pr_test_cases("drbgtestvectors/drbgvectors_pr_true/Hash_DRBG.rsp") {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(&trial.returned_bits).unwrap();

                let entropy = fill_pr_entropy(&trial);

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
                    name => unreachable!("Unexpected hash type {name} in PR test vectors."),
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
                let returned_bits = hex::decode(&trial.returned_bits).unwrap();

                let entropy = fill_pr_entropy(&trial);

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
                    name => unreachable!("Unexpected hmac type {name} in PR test vectors."),
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
                let returned_bits = hex::decode(&trial.returned_bits).unwrap();

                let entropy = fill_pr_entropy(&trial);

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

        for line in BufReader::new(file).lines().map(|l| l.unwrap()) {
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

    fn fill_no_pr_entropy(trial: &Trial) -> MockEntropy {
        let mut entropy = MockEntropy::default();
        entropy
            .bytes
            .push(hex::decode(&trial.entropy_input).unwrap());
        entropy
            .bytes
            .push(hex::decode(&trial.entropy_input_reseed).unwrap());
        entropy
    }

    #[test]
    fn test_no_pr_hash() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_no_pr_test_cases("drbgtestvectors/drbgvectors_no_reseed/Hash_DRBG.rsp")
        {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(&trial.returned_bits).unwrap();

                let entropy = fill_no_pr_entropy(&trial);

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
                    name => unreachable!("Unexpected hash type {name} in No-PR test vectors."),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_no_pr_hmac() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_no_pr_test_cases("drbgtestvectors/drbgvectors_no_reseed/HMAC_DRBG.rsp")
        {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(&trial.returned_bits).unwrap();

                let entropy = fill_no_pr_entropy(&trial);

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
                    name => unreachable!("Unexpected hmac type {name} in No-PR test vectors."),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_no_pr_ctr() -> Result<(), DrbgError<<MockEntropy as Entropy>::Error>> {
        for case in generate_no_pr_test_cases("drbgtestvectors/drbgvectors_no_reseed/CTR_DRBG.rsp")
        {
            for trial in case.trials {
                println!("{trial:#?}");
                let returned_bits = hex::decode(&trial.returned_bits).unwrap();

                let entropy = fill_no_pr_entropy(&trial);

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
