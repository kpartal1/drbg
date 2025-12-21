pub struct Pr;

pub struct NoPr;

pub trait PredictionResistance {
    fn is_pr() -> bool;
    fn must_reseed(reseed_counter: u64, max: u64) -> bool {
        reseed_counter > max
    }
}

impl PredictionResistance for Pr {
    fn is_pr() -> bool {
        true
    }
}

impl PredictionResistance for NoPr {
    fn is_pr() -> bool {
        false
    }
}
