use drbg::DrbgNoPrCtrAes256;

fn main() {
    println!("{:?}", DrbgNoPrCtrAes256::random_bytes(100, vec![], vec![]));
    let mut drbg = DrbgNoPrCtrAes256::new(vec![]);
    for _ in 0..10 {
        println!("{:?}", drbg.get_random_bytes(1 << 4, vec![]));
    }
}
