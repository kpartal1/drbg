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

    let len = (std::mem::size_of::<u32>() * 2 + input_string.len() + 1).div_ceil(C::BLOCK_LEN)
        * C::BLOCK_LEN;
    let mut s = Vec::with_capacity(len);
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

    let mut temp = Vec::with_capacity(C::SEED_LEN);
    let mut i = 0u32;
    while temp.len() < C::SEED_LEN {
        let mut iv_s = Vec::with_capacity(C::SEED_LEN + s.len());
        iv_s.extend(i.to_be_bytes());
        iv_s.extend(vec![0; C::BLOCK_LEN - std::mem::size_of::<u32>()]);
        iv_s.extend(&s);

        let bcc: C::V = bcc::<C>(&k, &iv_s);
        temp.extend(bcc.as_ref());
        i += 1;
    }

    let k = &temp[..C::KEY_LEN];
    let cipher = C::new(&C::key_from_slice(k));

    let mut x = C::block_from_slice(&temp[C::KEY_LEN..C::KEY_LEN + C::BLOCK_LEN]);
    let mut temp = Vec::with_capacity(C::SEED_LEN);
    while temp.len() < C::SEED_LEN {
        cipher.block_encrypt(&mut x);
        temp.extend(x.as_ref());
    }

    C::seed_from_slice(&temp[..C::SEED_LEN])
}

fn bcc<C: Cipher>(key: &C::Key, data: &[u8]) -> C::V {
    let cipher = C::new(key);

    let mut chaining_value = C::block_from_slice(&vec![0; C::BLOCK_LEN]);
    for block in data.chunks(C::BLOCK_LEN) {
        for (i, &b) in block.iter().enumerate() {
            chaining_value.as_mut()[i] ^= b;
        }

        cipher.block_encrypt(&mut chaining_value);
    }

    chaining_value
}
