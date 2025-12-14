pub mod ctr;
pub mod drbg;
pub mod pr;

use ctr::Ctr;
use ctr::cipher::Aes256;
use drbg::Drbg;
use pr::{NoPr, Pr};

pub type DrbgNoPrCtrAes256 = Drbg<Ctr<NoPr, Aes256>>;

pub type DrbgPrCtrAes256 = Drbg<Ctr<Pr, Aes256>>;

fn test() {
    let random_bytes = DrbgNoPrCtrAes256::get_random_bytes(10, None);
}
