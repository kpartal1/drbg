use crate::{
    drbg::variant::{DrbgVariant, GenerateInputInit, InstantiateInputInit, ReseedInputInit},
    hash_based::hashfn::HashFn,
};

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

pub struct HashInstantiateInput<F: HashFn> {
    entropy_input: F::Entropy,
    nonce: F::Nonce,
    personalization_string: Vec<u8>,
}

impl<F: HashFn> InstantiateInputInit for HashInstantiateInput<F> {
    fn init(entropy_input: &[u8], nonce: &[u8], personalization_string: &[u8]) -> Self {
        Self {
            entropy_input: F::entropy_from_slice(entropy_input),
            nonce: F::nonce_from_slice(nonce),
            personalization_string: Vec::from(personalization_string),
        }
    }
}

pub struct HashReseedInput<F: HashFn> {
    entropy_input: F::Entropy,
    additional_input: Vec<u8>,
}

impl<F: HashFn> ReseedInputInit for HashReseedInput<F> {
    fn init(entropy_input: &[u8], additional_input: &[u8]) -> Self {
        Self {
            entropy_input: F::entropy_from_slice(entropy_input),
            additional_input: Vec::from(additional_input),
        }
    }
}

pub struct HashGenerateInput {
    requested_number_of_bytes: usize,
    additional_input: Vec<u8>,
    reseed_counter: u64,
}

impl GenerateInputInit for HashGenerateInput {
    fn init(
        requested_number_of_bytes: usize,
        additional_input: &[u8],
        reseed_counter: u64,
    ) -> Self {
        Self {
            requested_number_of_bytes,
            additional_input: Vec::from(additional_input),
            reseed_counter,
        }
    }
}

impl<F: HashFn> DrbgVariant for Hash<F> {
    const MAX_RESEED_INTERVAL: u64 = 1 << 48;
    const SECURITY_STRENGTH: usize = F::SECURITY_STRENGTH;

    type InstantiateInput = HashInstantiateInput<F>;
    type ReseedInput = HashReseedInput<F>;
    type GenerateInput = HashGenerateInput;
    type GenerateError = std::convert::Infallible;

    fn instantiate(
        HashInstantiateInput {
            entropy_input,
            nonce,
            personalization_string,
        }: Self::InstantiateInput,
    ) -> Self {
        let mut seed_material = Vec::with_capacity(
            entropy_input.as_ref().len() + nonce.as_ref().len() + personalization_string.len(),
        );
        seed_material.extend(entropy_input.as_ref());
        seed_material.extend(nonce.as_ref());
        seed_material.extend(personalization_string);

        let seed = util::hash_df::<F>(&seed_material);
        let v = F::seed_from_slice(seed.as_ref());

        let mut c = Vec::with_capacity(std::mem::size_of::<u8>() + v.as_ref().len());
        c.push(0x00);
        c.extend(v.as_ref());
        let c = F::seed_from_slice(util::hash_df::<F>(&c).as_ref());
        Self { v, c }
    }

    fn reseed(
        &mut self,
        HashReseedInput {
            entropy_input,
            additional_input,
        }: Self::ReseedInput,
    ) {
        let mut seed_material = Vec::with_capacity(
            std::mem::size_of::<u8>()
                + self.v.as_ref().len()
                + entropy_input.as_ref().len()
                + additional_input.len(),
        );
        seed_material.push(0x01);
        seed_material.extend(self.v.as_ref());
        seed_material.extend(entropy_input.as_ref());
        seed_material.extend(additional_input);

        let seed = util::hash_df::<F>(&seed_material);
        self.v = F::seed_from_slice(seed.as_ref());

        let mut c = Vec::with_capacity(std::mem::size_of::<u8>() + self.v.as_ref().len());
        c.push(0x00);
        c.extend(self.v.as_ref());
        self.c = F::seed_from_slice(util::hash_df::<F>(&c).as_ref())
    }

    fn generate(
        &mut self,
        HashGenerateInput {
            requested_number_of_bytes,
            additional_input,
            reseed_counter,
        }: Self::GenerateInput,
    ) -> Result<Vec<u8>, Self::GenerateError> {
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

        let returned_bytes = self.hashgen(requested_number_of_bytes);

        let mut data = Vec::with_capacity(std::mem::size_of::<u8>() + self.v.as_ref().len());
        data.push(0x03);
        data.extend(self.v.as_ref());
        let h = F::hash(data);

        // Modular addition is associative.
        util::add(self.v.as_mut(), h.as_ref());
        util::add(self.v.as_mut(), self.c.as_ref());
        util::add(self.v.as_mut(), &reseed_counter.to_be_bytes());
        Ok(returned_bytes)
    }
}
