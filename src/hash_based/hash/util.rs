use crate::hash_based::hashfn::HashFn;

pub fn hash_df<F: HashFn>(input_string: &[u8]) -> F::Seed {
    let mut temp = Vec::with_capacity(F::SEED_LEN);
    let len = F::SEED_LEN.div_ceil(F::BLOCK_LEN);
    let mut counter = 0x01;
    for _ in 0..len {
        let cap = std::mem::size_of::<u8>() + std::mem::size_of::<u32>() + input_string.len();
        let mut c_n_i = Vec::with_capacity(cap);
        c_n_i.push(counter);
        c_n_i.extend((F::SEED_LEN as u32).to_be_bytes());
        c_n_i.extend(input_string);
        temp.extend(F::hash(&c_n_i).as_ref());
        counter += 1;
    }
    F::seed_from_slice(&temp[..F::SEED_LEN])
}
