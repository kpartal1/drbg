mod ctr;
mod drbg;
mod pr;

use ctr::{
    Ctr,
    cipher::{Aes128, Aes192, Aes256},
};
use drbg::Drbg;
use pr::{NoPr, Pr};

pub type DrbgNoPrCtrAes256 = Drbg<Ctr<NoPr, Aes256>>;
pub type DrbgPrCtrAes256 = Drbg<Ctr<Pr, Aes256>>;
pub type DrbgNoPrCtrAes192 = Drbg<Ctr<NoPr, Aes192>>;
pub type DrbgPrCtrAes192 = Drbg<Ctr<Pr, Aes192>>;
pub type DrbgNoPrCtrAes128 = Drbg<Ctr<NoPr, Aes128>>;
pub type DrbgPrCtrAes128 = Drbg<Ctr<Pr, Aes128>>;
