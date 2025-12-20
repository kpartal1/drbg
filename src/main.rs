use kondrbg::{DrbgCtrAes256, Entropy};

#[derive(Debug)]
struct NoEntropy;

impl Entropy for NoEntropy {
    type Error = std::convert::Infallible;
    fn try_fill_bytes(_: &mut [u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn main() {
    let drbg = DrbgCtrAes256::builder().entropy::<NoEntropy>().build();
    match drbg {
        Ok(mut drbg) => {
            for _ in 0..10 {
                let mut bytes = [0; 1];
                match drbg.fill_bytes(&mut bytes) {
                    Ok(_) => println!("{bytes:?}"),
                    Err(e) => println!("DRBG ERROR: {e}"),
                }
            }
        }
        Err(e) => println!("{e:?}"),
    }
}
