use crate::{drbg::variant::DrbgVariant, hash_based::hashfn::HashFn};

mod util;

pub struct Hash<F: HashFn> {
    v: F::Seed,
    c: F::Seed,
}

impl<F: HashFn> Hash<F> {
    fn hashgen(&self, bytes: &mut [u8]) {
        let mut data = self.v.clone();
        for block in bytes.chunks_mut(F::BLOCK_LEN) {
            let w = F::hash(data.as_ref());
            block.copy_from_slice(&w.as_ref()[..block.len()]);
            util::inc(data.as_mut());
        }
    }
}

impl<F: HashFn> DrbgVariant for Hash<F> {
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;
    const SECURITY_STRENGTH: usize = F::SECURITY_STRENGTH;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        let seed_material = [entropy_input, nonce, personalization_string].concat();
        let v = util::hash_df::<F>(&seed_material);

        let mut c = vec![0x00; std::mem::size_of::<u8>() + F::SEED_LEN];
        c[1..].copy_from_slice(v.as_ref());
        let c = util::hash_df::<F>(&c);
        Self { v, c }
    }

    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let seed_material = [&[0x01], self.v.as_ref(), entropy_input, additional_input].concat();
        self.v = util::hash_df::<F>(&seed_material);

        let mut c = vec![0x00; std::mem::size_of::<u8>() + F::SEED_LEN];
        c[1..].copy_from_slice(self.v.as_ref());
        self.c = util::hash_df::<F>(&c)
    }

    type GenerateError = std::convert::Infallible;
    fn generate(
        &mut self,
        bytes: &mut [u8],
        additional_input: &[u8],
        reseed_counter: u64,
    ) -> Result<(), Self::GenerateError> {
        if !additional_input.is_empty() {
            let data = [&[0x02], self.v.as_ref(), additional_input].concat();
            let w = F::hash(data);

            util::add(self.v.as_mut(), w.as_ref());
        }

        self.hashgen(bytes);

        let mut data = vec![0x03; std::mem::size_of::<u8>() + F::SEED_LEN];
        data[1..].copy_from_slice(self.v.as_ref());
        let h = F::hash(data);

        // Modular addition is associative.
        util::add(self.v.as_mut(), h.as_ref());
        util::add(self.v.as_mut(), self.c.as_ref());
        util::add(self.v.as_mut(), &reseed_counter.to_be_bytes());

        Ok(())
    }
}
