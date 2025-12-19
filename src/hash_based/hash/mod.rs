use crate::{drbg::variant::DrbgVariant, hash_based::hashfn::HashFn};

mod util;

pub struct Hash<F: HashFn> {
    v: F::Seed,
    c: F::Seed,
}

impl<F: HashFn> Hash<F> {
    fn hashgen(&self, requested_number_of_bytes: usize) -> Vec<u8> {
        let m = requested_number_of_bytes.div_ceil(F::BLOCK_LEN);
        let mut data = self.v.clone();
        let mut w = Vec::with_capacity(F::BLOCK_LEN * m);
        for _ in 0..m {
            let h = F::hash(data.as_ref());
            w.extend(h.as_ref());
            util::inc(data.as_mut());
        }
        Vec::from(&w[..requested_number_of_bytes])
    }
}

impl<F: HashFn> DrbgVariant for Hash<F> {
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;
    const SECURITY_STRENGTH: usize = F::SECURITY_STRENGTH;

    fn instantiate(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        let mut seed_material =
            Vec::with_capacity(entropy_input.len() + nonce.len() + personalization_string.len());
        seed_material.extend(entropy_input);
        seed_material.extend(nonce);
        seed_material.extend(personalization_string);

        let v = util::hash_df::<F>(&seed_material);

        let mut c = Vec::with_capacity(std::mem::size_of::<u8>() + v.as_ref().len());
        c.push(0x00);
        c.extend(v.as_ref());
        let c = F::seed_from_slice(util::hash_df::<F>(&c).as_ref());
        Self { v, c }
    }

    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let mut seed_material = Vec::with_capacity(
            std::mem::size_of::<u8>()
                + self.v.as_ref().len()
                + entropy_input.len()
                + additional_input.len(),
        );
        seed_material.push(0x01);
        seed_material.extend(self.v.as_ref());
        seed_material.extend(entropy_input);
        seed_material.extend(additional_input);

        self.v = util::hash_df::<F>(&seed_material);

        let mut c = Vec::with_capacity(std::mem::size_of::<u8>() + self.v.as_ref().len());
        c.push(0x00);
        c.extend(self.v.as_ref());
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
            let mut data = Vec::with_capacity(
                std::mem::size_of::<u8>() + self.v.as_ref().len() + additional_input.len(),
            );
            data.push(0x02);
            data.extend(self.v.as_ref());
            data.extend(additional_input);
            let w = F::hash(data);

            util::add(self.v.as_mut(), w.as_ref());
        }

        // let returned_bytes = self.hashgen(buf.len());

        let mut data = Vec::with_capacity(std::mem::size_of::<u8>() + self.v.as_ref().len());
        data.push(0x03);
        data.extend(self.v.as_ref());
        let h = F::hash(data);

        // Modular addition is associative.
        util::add(self.v.as_mut(), h.as_ref());
        util::add(self.v.as_mut(), self.c.as_ref());
        util::add(self.v.as_mut(), &reseed_counter.to_be_bytes());
        // Ok(returned_bytes)
        Ok(())
    }
}
