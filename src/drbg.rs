#[derive(Debug)]
pub enum GenerateError {
    ReseedRequired,
}

pub trait InstantiateInputInit {
    fn init(personalization_string: Option<&[u8]>) -> Self;
}

pub trait ReseedInputInit {
    fn init() -> Self;
}

pub trait GenerateInputInit {
    fn init() -> Self;
}

pub trait DrbgVariant {
    const MAX_RESEED_INTERVAL: u64;

    type WorkingState;
    type InstantiateInput: InstantiateInputInit;
    type ReseedInput: ReseedInputInit;
    type GenerateInput: GenerateInputInit;
    type GenerateOutput;

    fn instantiate(input: Self::InstantiateInput) -> Self;
    fn reseed(&mut self, input: Self::ReseedInput);
    fn generate(
        &mut self,
        input: Self::GenerateInput,
    ) -> Result<Self::GenerateOutput, GenerateError>;
}

pub struct Drbg<Variant: DrbgVariant> {
    variant: Variant,
}

impl<Variant: DrbgVariant> Drbg<Variant> {
    pub fn try_get_random_bytes(
        len: usize,
        personalization_string: Option<&[u8]>,
    ) -> Result<Vec<u8>, GenerateError> {
        let ii = <Variant as DrbgVariant>::InstantiateInput::init(personalization_string);
        let variant = <Variant as DrbgVariant>::instantiate(ii);
        todo!()
    }

    pub fn get_random_bytes(len: usize, personalization_string: Option<&[u8]>) -> Vec<u8> {
        Self::try_get_random_bytes(len, personalization_string)
            .expect("Failed to get random bytes.")
    }
}
