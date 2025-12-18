use drbg::{DrbgCtrAes256, DrbgPrCtrDrbgCtrAes256, Entropy};

#[derive(Debug)]
struct NoEntropy;

impl Entropy for NoEntropy {
    type Error = std::convert::Infallible;

    fn try_fill_bytes(_: &mut [u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn main() {
    let mut bytes = [0; 1 << 5];
    println!(
        "one-shot: {:?}",
        DrbgCtrAes256::builder()
            .entropy::<NoEntropy>()
            .random_bytes(&mut bytes)
    );
    let drbg = DrbgCtrAes256::builder().entropy::<NoEntropy>().build();
    match drbg {
        Ok(mut drbg) => {
            for _ in 0..10 {
                let mut bytes = [0; 1 << 4];
                drbg.get_random_bytes(&mut bytes, &[]).unwrap_or_else(|e| {
                    println!("{e:?}");
                });
                println!("{bytes:?}");
            }
        }
        Err(e) => println!("{e:?}"),
    }
}
