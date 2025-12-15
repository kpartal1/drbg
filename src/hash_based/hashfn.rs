pub trait HashFn {
    const BLOCK_LEN: usize;
    const SEED_LEN: usize;
    const SECURITY_STRENGTH: usize;

    const MAX_NUMBER_OF_BYTES_PER_REQUEST: u32 = 1 << 19;
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;

    type V;
    type C;
    type Key;
}
