#[derive(Debug)]
pub enum GenerateError {
    ReseedRequired,
}

pub trait InstantiateInputInit {
    fn init(personalization_string: &[u8]) -> Self;
}

pub trait ReseedInputInit {
    fn init(additional_input: &[u8]) -> Self;
}

pub trait GenerateInputInit {
    fn init(requested_number_of_bits: u32, additional_input: &[u8]) -> Self;
}

pub trait DrbgVariant: Sized {
    const MAX_RESEED_INTERVAL: u64;

    type WorkingState;
    type InstantiateInput: InstantiateInputInit;
    type ReseedInput: ReseedInputInit;
    type GenerateInput: GenerateInputInit;

    fn instantiate(input: Self::InstantiateInput) -> Self;
    fn reseed(&mut self, input: Self::ReseedInput);
    fn generate(&mut self, input: Self::GenerateInput) -> Result<Vec<u8>, GenerateError>;
}

pub struct Drbg<Variant: DrbgVariant>(Variant);

impl<Variant: DrbgVariant> Drbg<Variant> {
    pub fn new(personalization_string: Vec<u8>) -> Self {
        let ii = <Variant as DrbgVariant>::InstantiateInput::init(&personalization_string);
        Drbg(<Variant as DrbgVariant>::instantiate(ii))
    }

    pub fn get_random_bytes(
        &mut self,
        requested_number_of_bytes: u32,
        additional_input: Vec<u8>,
    ) -> Vec<u8> {
        let gi = <Variant as DrbgVariant>::GenerateInput::init(
            requested_number_of_bytes,
            &additional_input,
        );
        match self.0.generate(gi) {
            Ok(block) => block,
            Err(_) => {
                let ri = <Variant as DrbgVariant>::ReseedInput::init(&additional_input);
                self.0.reseed(ri);
                let gi = <Variant as DrbgVariant>::GenerateInput::init(
                    requested_number_of_bytes,
                    &additional_input,
                );
                self.0.generate(gi).unwrap()
            }
        }
    }

    pub fn random_bytes(
        requested_number_of_bytes: u32,
        personalization_string: Vec<u8>,
        additional_input: Vec<u8>,
    ) -> Vec<u8> {
        let ii = <Variant as DrbgVariant>::InstantiateInput::init(&personalization_string);
        let mut variant = <Variant as DrbgVariant>::instantiate(ii);
        let gi = <Variant as DrbgVariant>::GenerateInput::init(
            requested_number_of_bytes,
            &additional_input,
        );
        variant.generate(gi).unwrap() // This will never return Err because we just constructed the DRBG.
    }
}
