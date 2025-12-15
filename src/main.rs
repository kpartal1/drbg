use drbg::{DrbgNoPrCtrAes256, Entropy};

#[derive(Debug)]
struct NoEntropy;

impl Entropy for NoEntropy {
    type Error = std::convert::Infallible;

    fn try_fill_bytes(_: &mut [u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn main() {
    println!(
        "{:?}",
        DrbgNoPrCtrAes256::<NoEntropy>::new_with_entropy(vec![])
            .unwrap()
            .get_random_bytes(42, vec![])
    );
    match DrbgNoPrCtrAes256::new(vec![]) {
        Ok(mut drbg) => {
            for _ in 0..10 {
                match drbg.get_random_bytes(1 << 4, vec![]) {
                    Ok(bytes) => println!("random bytes: {bytes:?}"),
                    Err(e) => println!("{e:?}"),
                }
            }
        }
        Err(e) => println!("{e:?}"),
    }
}
