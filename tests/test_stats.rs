// 4 Statistical Tests for DRBGs as specified in SP800-22
// 1. The Frequency (Monobit) Test
// 2. Frequency Test Within a Block
// 3. The Runs Test
// 4. Tests for the Longest-Run-of-Ones in a Block
// NOTE: These tests fail occassionally, I'm pretty sure the DRBGs are still cryptographically secure.

#[cfg(test)]
mod tests {
    use kondrbg::{
        DrbgCtrAes128, DrbgCtrAes192, DrbgCtrAes256, DrbgError, DrbgHashSha224, DrbgHashSha256,
        DrbgHashSha384, DrbgHashSha512, DrbgHashSha512_224, DrbgHashSha512_256, DrbgHmacSha224,
        DrbgHmacSha256, DrbgHmacSha384, DrbgHmacSha512, DrbgHmacSha512_224, DrbgHmacSha512_256,
        DrbgPrCtrAes128, DrbgPrCtrAes192, DrbgPrCtrAes256, DrbgPrHashSha224, DrbgPrHashSha256,
        DrbgPrHashSha384, DrbgPrHashSha512, DrbgPrHashSha512_224, DrbgPrHashSha512_256,
        DrbgPrHmacSha224, DrbgPrHmacSha256, DrbgPrHmacSha384, DrbgPrHmacSha512,
        DrbgPrHmacSha512_224, DrbgPrHmacSha512_256,
    };
    use rand_core::{OsRng, TryRngCore};
    use special_fun::cephes_double::{erfc, igamc};

    type TestError = DrbgError<<OsRng as TryRngCore>::Error>;

    fn gen_with(bytes: &mut [u8], rng: &str) -> Result<(), TestError> {
        match rng {
            "drbg_hash_sha224" => DrbgHashSha224::new()?.fill_bytes(bytes),
            "drbg_pr_hash_sha224" => DrbgPrHashSha224::new()?.fill_bytes(bytes),
            "drbg_hash_sha256" => DrbgHashSha256::new()?.fill_bytes(bytes),
            "drbg_pr_hash_sha256" => DrbgPrHashSha256::new()?.fill_bytes(bytes),
            "drbg_hash_sha384" => DrbgHashSha384::new()?.fill_bytes(bytes),
            "drbg_pr_hash_sha384" => DrbgPrHashSha384::new()?.fill_bytes(bytes),
            "drbg_hash_sha512" => DrbgHashSha512::new()?.fill_bytes(bytes),
            "drbg_pr_hash_sha512" => DrbgPrHashSha512::new()?.fill_bytes(bytes),
            "drbg_hash_sha512/224" => DrbgHashSha512_224::new()?.fill_bytes(bytes),
            "drbg_pr_hash_sha512/224" => DrbgPrHashSha512_224::new()?.fill_bytes(bytes),
            "drbg_hash_sha512/256" => DrbgHashSha512_256::new()?.fill_bytes(bytes),
            "drbg_pr_hash_sha512/256" => DrbgPrHashSha512_256::new()?.fill_bytes(bytes),
            "drbg_hmac_sha224" => DrbgHmacSha224::new()?.fill_bytes(bytes),
            "drbg_pr_hmac_sha224" => DrbgPrHmacSha224::new()?.fill_bytes(bytes),
            "drbg_hmac_sha256" => DrbgHmacSha256::new()?.fill_bytes(bytes),
            "drbg_pr_hmac_sha256" => DrbgPrHmacSha256::new()?.fill_bytes(bytes),
            "drbg_hmac_sha384" => DrbgHmacSha384::new()?.fill_bytes(bytes),
            "drbg_pr_hmac_sha384" => DrbgPrHmacSha384::new()?.fill_bytes(bytes),
            "drbg_hmac_sha512" => DrbgHmacSha512::new()?.fill_bytes(bytes),
            "drbg_pr_hmac_sha512" => DrbgPrHmacSha512::new()?.fill_bytes(bytes),
            "drbg_hmac_sha512/224" => DrbgHmacSha512_224::new()?.fill_bytes(bytes),
            "drbg_pr_hmac_sha512/224" => DrbgPrHmacSha512_224::new()?.fill_bytes(bytes),
            "drbg_hmac_sha512/256" => DrbgHmacSha512_256::new()?.fill_bytes(bytes),
            "drbg_pr_hmac_sha512/256" => DrbgPrHmacSha512_256::new()?.fill_bytes(bytes),
            "drbg_ctr_aes128" => DrbgCtrAes128::new()?.fill_bytes(bytes),
            "drbg_pr_ctr_aes128" => DrbgPrCtrAes128::new()?.fill_bytes(bytes),
            "drbg_ctr_aes192" => DrbgCtrAes192::new()?.fill_bytes(bytes),
            "drbg_pr_ctr_aes192" => DrbgPrCtrAes192::new()?.fill_bytes(bytes),
            "drbg_ctr_aes256" => DrbgCtrAes256::new()?.fill_bytes(bytes),
            "drbg_pr_ctr_aes256" => DrbgPrCtrAes256::new()?.fill_bytes(bytes),
            name => unreachable!(
                "Invalid Drbg name: {name}. Valid names are of the form drbg_?(pr_)(hash|hmac|ctr)_(sha224|sha256|sha384|sha512|sha512/224|sha512/256|aes128|aes192|aes256)"
            ),
        }
    }

    fn test_all(bytes: &mut [u8], f: fn(&[u8]) -> f64) -> Result<(), TestError> {
        test_one(bytes, f, "drbg_hash_sha224")?;
        test_one(bytes, f, "drbg_pr_hash_sha224")?;
        test_one(bytes, f, "drbg_hash_sha256")?;
        test_one(bytes, f, "drbg_pr_hash_sha256")?;
        test_one(bytes, f, "drbg_hash_sha384")?;
        test_one(bytes, f, "drbg_pr_hash_sha384")?;
        test_one(bytes, f, "drbg_hash_sha512")?;
        test_one(bytes, f, "drbg_pr_hash_sha512")?;
        test_one(bytes, f, "drbg_hash_sha512/224")?;
        test_one(bytes, f, "drbg_pr_hash_sha512/224")?;
        test_one(bytes, f, "drbg_hash_sha512/256")?;
        test_one(bytes, f, "drbg_pr_hash_sha512/256")?;
        test_one(bytes, f, "drbg_hmac_sha224")?;
        test_one(bytes, f, "drbg_pr_hmac_sha224")?;
        test_one(bytes, f, "drbg_hmac_sha256")?;
        test_one(bytes, f, "drbg_pr_hmac_sha256")?;
        test_one(bytes, f, "drbg_hmac_sha384")?;
        test_one(bytes, f, "drbg_pr_hmac_sha384")?;
        test_one(bytes, f, "drbg_hmac_sha512")?;
        test_one(bytes, f, "drbg_pr_hmac_sha512")?;
        test_one(bytes, f, "drbg_hmac_sha512/224")?;
        test_one(bytes, f, "drbg_pr_hmac_sha512/224")?;
        test_one(bytes, f, "drbg_hmac_sha512/256")?;
        test_one(bytes, f, "drbg_pr_hmac_sha512/256")?;
        test_one(bytes, f, "drbg_ctr_aes128")?;
        test_one(bytes, f, "drbg_pr_ctr_aes128")?;
        test_one(bytes, f, "drbg_ctr_aes192")?;
        test_one(bytes, f, "drbg_pr_ctr_aes192")?;
        test_one(bytes, f, "drbg_ctr_aes256")?;
        test_one(bytes, f, "drbg_pr_ctr_aes256")?;
        Ok(())
    }

    const RUNS: usize = 1_000;

    fn test_one(bytes: &mut [u8], f: fn(&[u8]) -> f64, rng: &str) -> Result<(), TestError> {
        let mut p_vals = Vec::with_capacity(RUNS);
        for _ in 0..RUNS {
            gen_with(bytes, rng)?;
            p_vals.push(f(bytes));
        }
        println!();
        println!("vvvvvvvvvv {rng} vvvvvvvvvv");
        println!("BYTES: {}", bytes.len());
        println!("RUNS: {RUNS}");
        println!("SIGNIFICANCE LEVEL: {SIGNIFICANCE_LEVEL}");
        println!();
        println!("========== PROPORTION TEST ==========");
        proportion_of_sequences_passing_a_test(SIGNIFICANCE_LEVEL, &p_vals);
        println!("=====================================");
        println!();
        println!("========== DISTRIBUTION TEST ==========");
        uniform_distribution_of_p_vals_test(&p_vals);
        println!("=======================================");
        println!("^^^^^^^^^^ {rng} ^^^^^^^^^^");
        Ok(())
    }

    const SIGNIFICANCE_LEVEL: f64 = 0.01;

    fn proportion_of_sequences_passing_a_test(significance_level: f64, p_vals: &[f64]) {
        let p_hat = 1f64 - significance_level;
        let m = p_vals.len() as f64;
        let confidence = p_hat - 3f64 * ((p_hat * significance_level) / m).sqrt();
        let proportion = p_vals
            .iter()
            .filter(|&&p_val| p_val >= significance_level)
            .count() as f64
            / m;
        println!(
            "PROPORTION OF SEQUENCES PASSING A TEST WITH SIGNIFICANCE LEVEL {significance_level}:"
        );
        println!("PROPORTION {proportion} MUST BE >= CONFIDENCE {confidence}");
        if proportion >= confidence {
            println!("SUCCESS!");
        } else {
            println!("FAILURE :(");
        }
        assert!(proportion >= confidence)
    }

    const UNIFORM_DIST_CHUNKS: f64 = 10f64;

    fn uniform_distribution_of_p_vals_test(p_vals: &[f64]) {
        let s = p_vals.len() as f64 / UNIFORM_DIST_CHUNKS;
        let mut chi_squared = 0f64;
        for (lower, upper) in (0..).zip(1..=UNIFORM_DIST_CHUNKS as i32) {
            let (lower, upper) = (
                lower as f64 / UNIFORM_DIST_CHUNKS,
                upper as f64 / UNIFORM_DIST_CHUNKS,
            );
            let f_i = p_vals
                .iter()
                .filter(|&&p_val| p_val > lower && p_val <= upper)
                .count() as f64;
            chi_squared += (f_i - s).powi(2) / s;
        }
        let p_val_t = igamc(9f64 / 2f64, chi_squared / 2f64);
        println!("UNIFORM DISTRIBUTION OF P-VALUES TEST:");
        println!("P-VALUE_T {p_val_t} MUST BE >= 0.0001");
        if p_val_t >= 0.0001 {
            println!("SUCCESS!");
        } else {
            println!("FAILURE :(");
        }
        assert!(p_val_t >= 0.0001);
    }

    fn monobit(bytes: &[u8]) -> f64 {
        let n = (bytes.len() * 8) as f64;
        let s_n = bytes.iter().fold(0, |acc, byte| {
            let ones = byte.count_ones() as i32;
            let zeros = byte.count_zeros() as i32;
            acc + (ones - zeros)
        });
        let s_obs = s_n.abs() as f64 / n.sqrt();
        erfc(s_obs / 2f64.sqrt())
    }

    #[test]
    fn monobit_test() -> Result<(), TestError> {
        let mut bytes = [0; 1 << 11];
        test_all(&mut bytes, monobit)
    }

    const BLOCK_LEN: usize = 16;

    fn freq_within_block(bytes: &[u8]) -> f64 {
        let n = (bytes.len() / BLOCK_LEN) as f64;
        let mut chi_square = 0f64;
        for block in bytes.chunks_exact(BLOCK_LEN) {
            let pi = block.iter().fold(0, |acc, byte| acc + byte.count_ones()) as f64
                / (BLOCK_LEN * 8) as f64;
            chi_square += (pi - 0.5).powi(2);
        }
        chi_square *= 4f64 * (BLOCK_LEN * 8) as f64;
        igamc(n / 2f64, chi_square / 2f64)
    }

    #[test]
    fn freq_within_block_test() -> Result<(), TestError> {
        let mut bytes = [0; 1 << 6];
        test_all(&mut bytes, freq_within_block)
    }

    fn runs(bytes: &[u8]) -> f64 {
        let n = (bytes.len() * 8) as f64;
        let pi = bytes.iter().fold(0, |acc, byte| acc + byte.count_ones()) as f64 / n;
        let v_obs = {
            let mut runs = 0;
            let mut prev = (bytes[0] >> 7) & 1;
            for byte in bytes {
                for bit_pos in (0..8).rev() {
                    let bit = (byte >> bit_pos) & 1;
                    if bit != prev {
                        runs += 1;
                        prev = bit;
                    }
                }
            }
            runs + 1
        } as f64;
        erfc(
            (v_obs - (2f64 * n * pi * (1f64 - pi))).abs()
                / (2f64 * (2f64 * n).sqrt() * pi * (1f64 - pi)),
        )
    }

    #[test]
    fn runs_test() -> Result<(), TestError> {
        let mut bytes = [0; 1 << 11];
        test_all(&mut bytes, runs)
    }

    fn longest_run_of_ones_in_block(bytes: &[u8]) -> f64 {
        let len = bytes.len() * 8;
        let (m, k, n, v_pi) = if len == 128 {
            (
                1,
                3,
                16f64,
                Vec::from([(1, 0.2148), (2, 0.3672), (3, 0.2305), (4, 0.1875)]),
            )
        } else if len == 6272 {
            (
                128 / 8,
                5,
                49f64,
                Vec::from([
                    (4, 0.1174),
                    (5, 0.2430),
                    (6, 0.2493),
                    (7, 0.1752),
                    (8, 0.1027),
                    (9, 0.1124),
                ]),
            )
        } else if len == 750_000 {
            (
                10_000 / 8,
                6,
                75f64,
                Vec::from([
                    (10, 0.0882),
                    (11, 0.2092),
                    (12, 0.2483),
                    (13, 0.1933),
                    (14, 0.1208),
                    (15, 0.0675),
                    (16, 0.0727),
                ]),
            )
        } else {
            panic!(
                "Invalid size in longest_run_of_ones_in_block. Must be 128, 6272, or 750_000 bits (16, 784, 93_750 bytes, respectively)."
            );
        };
        let mut max_runs = Vec::new();
        for block in bytes.chunks(m) {
            let mut max_run = 0;
            let mut current_run = 0;

            for byte in block {
                for i in (0..8).rev() {
                    if (byte >> i) & 1 == 1 {
                        current_run += 1;
                        if current_run > max_run {
                            max_run = current_run;
                        }
                    } else {
                        current_run = 0;
                    }
                }
            }

            max_runs.push(max_run);
        }
        let mut chi_squared = 0f64;

        let (v, pi) = v_pi[0];
        let v = max_runs.iter().filter(|&&run| run <= v).count() as f64;
        chi_squared += (v - n * pi).powi(2) / (n * pi);

        for (v, pi) in v_pi.iter().take(k).skip(1) {
            let v = max_runs.iter().filter(|&run| run == v).count() as f64;
            chi_squared += (v - n * pi).powi(2) / (n * pi);
        }

        let (v, pi) = v_pi[v_pi.len() - 1];
        let v = max_runs.iter().filter(|&&run| run >= v).count() as f64;
        chi_squared += (v - n * pi).powi(2) / (n * pi);
        igamc(k as f64 / 2f64, chi_squared / 2f64)
    }

    #[test]
    fn longest_run_of_ones_in_block_test() -> Result<(), TestError> {
        let mut bytes = [0; 784];
        test_all(&mut bytes, longest_run_of_ones_in_block)
    }
}
