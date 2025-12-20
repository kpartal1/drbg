use crate::hash_based::hashfn::HashFn;

pub fn inc(block: &mut [u8]) {
    for byte in block.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

pub fn add(fst: &mut [u8], snd: &[u8]) {
    let mut carry = 0u8;

    let mut i = fst.len();
    let mut j = snd.len();

    while i > 0 {
        i -= 1;

        let b = if j > 0 {
            j -= 1;
            snd[j]
        } else {
            0
        };

        let (sum1, c1) = fst[i].overflowing_add(b);
        let (sum2, c2) = sum1.overflowing_add(carry);

        fst[i] = sum2;
        carry = (c1 | c2) as u8;
    }
}

pub fn hash_df<F: HashFn>(input_string: &[u8]) -> F::Seed {
    let mut temp = vec![0; F::SEED_LEN];
    for (counter, block) in (0x01..).zip(temp.chunks_mut(F::BLOCK_LEN)) {
        let no_bytes = (F::SEED_LEN as u32).to_be_bytes();
        let data = [&[counter], no_bytes.as_slice(), input_string].concat();
        block.copy_from_slice(&F::hash(&data).as_ref()[..block.len()]);
    }
    F::seed_from_slice(&temp[..F::SEED_LEN])
}
