use crate::ctr::Cipher;

pub fn inc(block: &mut [u8]) {
    for byte in block.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

pub fn block_cipher_df<C: Cipher>(input_string: &[u8]) -> C::Seed {
    let l = input_string.len() as u32;
    let n = C::SEED_LEN as u32;

    let cap = C::BLOCK_LEN
        + (std::mem::size_of::<u32>() * 2 + input_string.len() + 1).div_ceil(C::BLOCK_LEN)
            * C::BLOCK_LEN;
    let mut s = Vec::with_capacity(cap);
    s.resize(C::BLOCK_LEN, 0); // Prepend IV
    s.extend(l.to_be_bytes());
    s.extend(n.to_be_bytes());
    s.extend(input_string);
    s.push(0x80);
    while !s.len().is_multiple_of(C::BLOCK_LEN) {
        s.push(0);
    }

    let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
              \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    let k = C::key_from_slice(&k[..C::KEY_LEN]);

    let mut temp = C::seed_from_slice(&vec![0; C::SEED_LEN]);
    for block in temp.as_mut().chunks_mut(C::BLOCK_LEN) {
        let chain = bcc::<C>(&k, &s);
        block.copy_from_slice(&chain.as_ref()[..block.len()]);
        inc(&mut s[..std::mem::size_of::<u32>()]); // Increment IV
    }

    let (k, mut x) = C::seed_to_key_block(temp);
    let cipher = C::new(&k);

    let mut temp = C::seed_from_slice(&vec![0; C::SEED_LEN]);
    for block in temp.as_mut().chunks_mut(C::BLOCK_LEN) {
        cipher.block_encrypt(&mut x);
        block.copy_from_slice(&x.as_ref()[..block.len()]);
    }

    temp
}

fn bcc<C: Cipher>(key: &C::Key, data: &[u8]) -> C::Block {
    let cipher = C::new(key);

    let mut chaining_value = C::block_from_slice(&vec![0; C::BLOCK_LEN]);
    for block in data.chunks(C::BLOCK_LEN) {
        for (byte, chaining_byte) in block.iter().zip(chaining_value.as_mut()) {
            *chaining_byte ^= byte;
        }
        cipher.block_encrypt(&mut chaining_value);
    }
    chaining_value
}
