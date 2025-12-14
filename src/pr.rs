pub struct Pr;
pub struct NoPr;

pub trait PredictionResistance {
    fn must_reseed(reseed_counter: u64, max: u64) -> bool;
}

impl PredictionResistance for Pr {
    fn must_reseed(_: u64, _: u64) -> bool {
        true
    }
}

impl PredictionResistance for NoPr {
    fn must_reseed(reseed_counter: u64, max: u64) -> bool {
        reseed_counter > max
    }
}
