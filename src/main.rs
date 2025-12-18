use drbg::{DrbgNoPrHmacSha512, DrbgPrHmacSha512, Entropy};

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
        DrbgNoPrHmacSha512::<NoEntropy>::random_bytes_with_entropy(42, vec![], vec![])
    );
    println!("{:?}", DrbgNoPrHmacSha512::random_bytes(42, vec![], vec![]));
    let mut e = DrbgNoPrHmacSha512::default();
    println!("{:?}", e.get_random_bytes(42, vec![]));
    match DrbgPrHmacSha512::new(vec![]) {
        Ok(mut drbg) => {
            for _ in 0..10 {
                match drbg.get_random_bytes(1 << 4, vec![]) {
                    Ok(bytes) => println!("random bytes: {bytes:?}"),
                    Err(e) => println!("errro: {e:?}"),
                }
            }
        }
        Err(e) => println!("{e:?}"),
    }
}
